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

import io.ktor.client.engine.HttpClientEngineBase
import io.ktor.client.engine.HttpClientEngineConfig
import io.ktor.client.engine.callContext
import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.HttpResponseData
import io.ktor.http.Headers
import io.ktor.http.HttpProtocolVersion
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.OutgoingContent
import io.ktor.util.date.GMTDate
import io.ktor.utils.io.ByteReadChannel
import kotlinx.coroutines.currentCoroutineContext
import java.net.URI

@OptIn(io.ktor.utils.io.InternalAPI::class, kotlinx.coroutines.InternalCoroutinesApi::class)
class BoundedKtorEngine(private val transport: BoundedHttpTransport) : HttpClientEngineBase("address-bound") {
    override val config = HttpClientEngineConfig()

    override suspend fun execute(data: HttpRequestData): HttpResponseData {
        val started = GMTDate()
        val body = when (val content = data.body) {
            is OutgoingContent.NoContent -> byteArrayOf()
            is OutgoingContent.ByteArrayContent -> content.bytes()
            else -> error("Streaming outbound request bodies are unsupported by the bounded fetch contract")
        }
        val headers = data.headers.entries().flatMap { (name, values) -> values.map { name to it } }.toMutableList()
        data.body.contentType?.let {
            if (headers.none {
                    it.first.equals(
                        "Content-Type",
                        true,
                    )
                }
            ) headers.add("Content-Type" to it.toString())
        }
        val cancellation = BoundedHttpTransport.Cancellation()
        val handle = currentCoroutineContext()[kotlinx.coroutines.Job]?.invokeOnCompletion(
            onCancelling = true,
            invokeImmediately = true,
        ) { cause ->
            if (cause != null) cancellation.abort()
        }
        val response = try {
            transport.execute(URI(data.url.toString()), data.method.value, headers, body, cancellation)
        } finally { handle?.dispose() }
        return HttpResponseData(
            HttpStatusCode.fromValue(response.status),
            started,
            Headers.build { response.headers.forEach { (name, value) -> append(name, value) } },
            HttpProtocolVersion.HTTP_1_1,
            ByteReadChannel(response.body),
            callContext(),
        )
    }
}
