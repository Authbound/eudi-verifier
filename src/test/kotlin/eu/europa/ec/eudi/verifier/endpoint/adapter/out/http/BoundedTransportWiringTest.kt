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

import io.ktor.client.HttpClient
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import kotlinx.coroutines.runBlocking
import org.apache.http.HttpHost
import org.apache.http.HttpRequest
import org.apache.http.HttpVersion
import org.apache.http.client.methods.CloseableHttpResponse
import org.apache.http.client.methods.HttpUriRequest
import org.apache.http.impl.client.CloseableHttpClient
import org.apache.http.message.BasicHttpResponse
import org.apache.http.protocol.HttpContext
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.net.InetAddress
import java.net.URI

class BoundedTransportWiringTest {
    private fun fakeClient(handle: (HttpHost, HttpRequest) -> CloseableHttpResponse): CloseableHttpClient = object : CloseableHttpClient() {
        override fun doExecute(
            target: HttpHost,
            request: HttpRequest,
            context: HttpContext?,
        ): CloseableHttpResponse = handle(target, request)
        override fun close() = Unit
        override fun getParams(): org.apache.http.params.HttpParams = org.apache.http.params.BasicHttpParams()
        override fun getConnectionManager(): org.apache.http.conn.ClientConnectionManager = error("No real connection manager in fixture")
    }

    private fun response(status: Int, body: String = "{}"): CloseableHttpResponse = object :
        BasicHttpResponse(
            HttpVersion.HTTP_1_1,
            status,
            "fixture",
        ),
        CloseableHttpResponse {
        init { entity = org.apache.http.entity.StringEntity(body, org.apache.http.entity.ContentType.APPLICATION_JSON) }
        override fun close() = Unit
    }

    @Test
    fun `Ktor public fetch preserves authority and sends only the once validated answers to dialer`() = runBlocking {
        var lookups = 0
        var requests = 0
        val address = InetAddress.getByAddress(byteArrayOf(8, 8, 8, 8))
        val transport = BoundedHttpTransport.forTests(OutboundPolicy.Public, lookup = { host ->
            assertEquals("wallet.example", host)
            lookups++
            arrayOf(address)
        }, openClient = { bound ->
            assertArrayEquals(arrayOf(address), bound.resolve("wallet.example"))
            assertArrayEquals(arrayOf(address), bound.resolve("wallet.example"))
            fakeClient { target, request ->
                requests++
                assertEquals("wallet.example", target.hostName)
                assertEquals("GET", request.requestLine.method)
                assertNull(request.getFirstHeader("X-Internal-Token"))
                response(200, "{\"keys\":[]}")
            }
        })
        HttpClient(BoundedKtorEngine(transport)).use { client ->
            assertEquals("{\"keys\":[]}", client.get("https://wallet.example/keys").bodyAsText())
        }
        assertEquals(1, lookups)
        assertEquals(1, requests)
    }

    @Test
    fun `mixed private DNS cannot reach connection factory`() {
        var opened = false
        val transport = BoundedHttpTransport.forTests(OutboundPolicy.Public, lookup = {
            arrayOf(InetAddress.getByAddress(byteArrayOf(8, 8, 8, 8)), InetAddress.getByAddress(byteArrayOf(10, 0, 0, 1)))
        }, openClient = {
            opened = true
            error("Unexpected dial")
        })
        assertThrows(IllegalArgumentException::class.java) { transport.execute(URI("https://wallet.example/keys")) }
        assertFalse(opened)
    }

    @Test
    fun `internal callback serialization keeps exact path and token isolated from public client`() = runBlocking {
        val endpoint = URI("http://pension-backend:3010/internal/eudi-verifier/presentations/wallet-response")
        val transport = BoundedHttpTransport.forTests(OutboundPolicy.exactInternal(endpoint, "POST"), true, lookup = {
            arrayOf(InetAddress.getByAddress(byteArrayOf(172.toByte(), 20, 0, 2)))
        }, openClient = { bound ->
            assertEquals("pension-backend", bound.host)
            fakeClient { target, request ->
                assertEquals("pension-backend", target.hostName)
                assertEquals(3010, target.port)
                assertEquals("POST", request.requestLine.method)
                assertEquals("synthetic", request.getFirstHeader("X-Internal-Token").value)
                assertTrue(request.requestLine.uri.endsWith(endpoint.rawPath))
                val bytes = (request as org.apache.http.HttpEntityEnclosingRequest).entity.content.readBytes()
                assertEquals("{\"callback\":\"synthetic\"}", bytes.toString(Charsets.UTF_8))
                response(200)
            }
        })
        HttpClient(BoundedKtorEngine(transport)) { install(ContentNegotiation) { json() } }.use { client ->
            client.post(endpoint.toString()) {
                contentType(ContentType.Application.Json)
                headers.append("X-Internal-Token", "synthetic")
                setBody(mapOf("callback" to "synthetic"))
            }
        }
    }

    @Test
    fun `redirect is rejected once and request aborted without forwarding credentials`() {
        var requests = 0
        lateinit var request: HttpUriRequest
        val transport = BoundedHttpTransport.forTests(OutboundPolicy.Public, lookup = {
            arrayOf(InetAddress.getByAddress(byteArrayOf(8, 8, 8, 8)))
        }, openClient = {
            fakeClient { _, incoming ->
                request = incoming as HttpUriRequest
                requests++
                response(302).apply { addHeader("Location", "http://169.254.169.254/latest/meta-data/") }
            }
        })
        assertThrows(IllegalArgumentException::class.java) { transport.execute(URI("https://wallet.example/keys")) }
        assertEquals(1, requests)
        assertTrue(request.isAborted)
    }
}
