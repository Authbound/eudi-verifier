/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.http

import org.apache.http.client.config.RequestConfig
import org.apache.http.client.methods.RequestBuilder
import org.apache.http.entity.ByteArrayEntity
import org.apache.http.impl.client.HttpClients
import java.io.InputStream
import java.net.InetAddress
import java.net.URI
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.Executors
import java.util.concurrent.Semaphore
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

/** A fresh direct connection per request keeps validated DNS answers attached to the actual dial. */
class BoundedHttpTransport private constructor(
    private val policy: OutboundPolicy,
    private val credentialsAllowed: Boolean,
    private val lookup: (String) -> Array<InetAddress>,
    private val openClient: (BoundDestination) -> org.apache.http.impl.client.CloseableHttpClient,
) {
    constructor(
        policy: OutboundPolicy,
        credentialsAllowed: Boolean = false,
    ) : this(policy, credentialsAllowed, ::lookupWithBudget, ::addressBoundClient)

    data class Response(val status: Int, val headers: List<Pair<String, String>>, val body: ByteArray)

    fun execute(
        uri: URI,
        method: String = "GET",
        headers: List<Pair<String, String>> = emptyList(),
        body: ByteArray = byteArrayOf(),
        cancellation: Cancellation = Cancellation(),
    ): Response {
        cancellation.checkActive()
        require(headers.size <= 64 && headers.all { it.first.length + it.second.length <= 8192 }) { "Outbound header budget exceeded" }
        require(body.size <= MAX_BYTES) { "Outbound request body exceeds budget" }
        require(
            headers.none {
                    (name, _) ->
                name.equals("Host", true) || name.equals("Proxy-Authorization", true) || name.equals("Cookie", true)
            },
        ) { "Outbound authority or credential forwarding is forbidden" }
        require(
            credentialsAllowed || headers.none {
                    (name, _) ->
                name.equals("Authorization", true) || name.equals("X-Internal-Token", true)
            },
        ) { "Credentials forbidden on public fetch transport" }
        require(active.tryAcquire()) { "Outbound concurrency budget exceeded" }
        try {
            val bound = policy.bind(uri, method, lookup)
            val request = RequestBuilder.create(method).setUri(uri).apply {
                headers.filterNot {
                    it.first.lowercase() in setOf("accept-encoding", "content-length", "transfer-encoding", "connection")
                }.forEach { (name, value) -> addHeader(name, value) }
                setHeader("Accept-Encoding", "identity")
                if (body.isNotEmpty()) setEntity(ByteArrayEntity(body))
            }.build()
            cancellation.attach(request)
            val abort = deadlines.schedule({ request.abort() }, 8, TimeUnit.SECONDS)
            try {
                openClient(bound).use { client ->
                    client.execute(request).use { response ->
                        return consumeResponse(response, request::abort)
                    }
                }
            } finally { abort.cancel(false) }
        } finally { active.release() }
    }

    internal fun consumeResponse(response: org.apache.http.HttpResponse, abort: () -> Unit): Response {
        try {
            require(response.statusLine.statusCode !in 300..399) { "Outbound redirects are forbidden" }
            require(
                response.allHeaders.filter {
                    it.name.equals("Content-Encoding", true)
                }.all { it.value.trim().equals("identity", true) },
            ) { "Compressed outbound responses are unsupported" }
            val entity = response.entity
            require(entity == null || entity.contentLength <= MAX_BYTES) { "Outbound response exceeds budget" }
            // Let the response own closure. On rejection abort first, so Apache cannot drain the remaining entity.
            val bytes = entity?.content?.let(::readBounded) ?: byteArrayOf()
            return Response(response.statusLine.statusCode, response.allHeaders.map { it.name to it.value }, bytes)
        } catch (failure: Throwable) {
            abort()
            throw failure
        }
    }

    class Cancellation {
        private var aborted = false
        private var request: org.apache.http.client.methods.HttpUriRequest? = null

        @Synchronized internal fun checkActive() { require(!aborted) { "Outbound call cancelled" } }

        @Synchronized fun abort() {
            aborted = true
            request?.abort()
        }

        @Synchronized internal fun attach(value: org.apache.http.client.methods.HttpUriRequest) {
            require(!aborted) { "Outbound call cancelled" }
            request = value
        }
    }

    companion object {
        const val MAX_BYTES = 1_048_576
        private val active = Semaphore(16)
        private val daemonFactory = java.util.concurrent.ThreadFactory {
                task ->
            Thread(task, "verifier-bounded-egress").apply { isDaemon = true }
        }
        private val dns =
            ThreadPoolExecutor(4, 4, 0, TimeUnit.SECONDS, ArrayBlockingQueue(16), daemonFactory, ThreadPoolExecutor.AbortPolicy())
        private val deadlines = Executors.newSingleThreadScheduledExecutor(daemonFactory)

        private fun lookupWithBudget(host: String): Array<InetAddress> {
            val answer = dns.submit<Array<InetAddress>> { InetAddress.getAllByName(host) }
            return try { answer.get(2, TimeUnit.SECONDS) } finally { answer.cancel(true) }
        }

        private fun addressBoundClient(bound: BoundDestination): org.apache.http.impl.client.CloseableHttpClient =
            HttpClients.custom()
                .setDnsResolver { host -> bound.resolve(host) }
                .setDefaultConnectionConfig(
                    org.apache.http.config.ConnectionConfig.custom().setMessageConstraints(
                        org.apache.http.config.MessageConstraints.custom().setMaxHeaderCount(64).setMaxLineLength(8192).build(),
                    ).build(),
                )
                .disableRedirectHandling().disableCookieManagement().disableContentCompression().disableAutomaticRetries()
                .setDefaultRequestConfig(
                    RequestConfig.custom().setConnectTimeout(
                        2_000,
                    ).setConnectionRequestTimeout(2_000).setSocketTimeout(5_000).setRedirectsEnabled(false).build(),
                )
                .build()

        internal fun forTests(
            policy: OutboundPolicy,
            credentialsAllowed: Boolean = false,
            lookup: (String) -> Array<InetAddress>,
            openClient: (BoundDestination) -> org.apache.http.impl.client.CloseableHttpClient,
        ): BoundedHttpTransport = BoundedHttpTransport(policy, credentialsAllowed, lookup, openClient)

        internal fun readBounded(input: InputStream): ByteArray {
            val result = java.io.ByteArrayOutputStream()
            val buffer = ByteArray(8192)
            while (true) {
                val read = input.read(buffer, 0, minOf(buffer.size, MAX_BYTES - result.size() + 1))
                if (read < 0) break
                require(result.size() + read <= MAX_BYTES) { "Outbound response exceeds budget" }
                result.write(buffer, 0, read)
            }
            return result.toByteArray()
        }
    }
}
