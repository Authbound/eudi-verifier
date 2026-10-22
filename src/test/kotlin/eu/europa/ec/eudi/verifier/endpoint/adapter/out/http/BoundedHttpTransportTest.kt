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

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.net.URI

class BoundedHttpTransportTest {
    @Test
    fun `rejected response is aborted before Apache style stream closure can drain it`() {
        for ((status, encoding, length) in listOf(
            Triple(302, null, -1L),
            Triple(200, "gzip", -1L),
            Triple(200, null, BoundedHttpTransport.MAX_BYTES + 1L),
            Triple(200, null, -1L),
        )) {
            var aborted = false
            val stream = object : java.io.InputStream() {
                var consumed = 0
                override fun read(): Int {
                    consumed++
                    return if (consumed <= BoundedHttpTransport.MAX_BYTES + 32_768) 1 else -1
                }
                override fun read(bytes: ByteArray, offset: Int, count: Int): Int {
                    val left = BoundedHttpTransport.MAX_BYTES + 32_768 - consumed
                    if (left <= 0) return -1
                    val n = minOf(count, left)
                    consumed += n
                    return n
                }
                override fun close() { if (!aborted) while (read() != -1) { } }
            }
            val response = object :
                org.apache.http.message.BasicHttpResponse(
                    org.apache.http.HttpVersion.HTTP_1_1,
                    status,
                    "fixture",
                ),
                org.apache.http.client.methods.CloseableHttpResponse {
                override fun close() { stream.close() }
            }
            response.entity = org.apache.http.entity.BasicHttpEntity().apply {
                content = stream
                contentLength = length
            }
            encoding?.let { response.addHeader("Content-Encoding", it) }
            assertThrows(IllegalArgumentException::class.java) {
                response.use { BoundedHttpTransport(OutboundPolicy.Public).consumeResponse(it) { aborted = true } }
            }
            assertTrue(aborted)
            assertEquals(if (status == 200 && encoding == null && length == -1L) BoundedHttpTransport.MAX_BYTES + 1 else 0, stream.consumed)
        }
    }

    @Test
    fun `oversized unknown stream consumes at most the budget and one sentinel byte`() {
        val stream = object : java.io.InputStream() {
            var consumed = 0
            override fun read(): Int {
                consumed++
                return 1
            }
            override fun read(bytes: ByteArray, offset: Int, length: Int): Int {
                consumed += length
                return length
            }
        }
        assertThrows(IllegalArgumentException::class.java) { BoundedHttpTransport.readBounded(stream) }
        assertEquals(BoundedHttpTransport.MAX_BYTES + 1, stream.consumed)
    }

    @Test
    fun `response body boundary is bounded while preserving exact bytes`() {
        val bytes = ByteArray(BoundedHttpTransport.MAX_BYTES) { (it % 251).toByte() }
        assertArrayEquals(bytes, BoundedHttpTransport.readBounded(ByteArrayInputStream(bytes)))
        assertThrows(IllegalArgumentException::class.java) {
            BoundedHttpTransport.readBounded(ByteArrayInputStream(ByteArray(BoundedHttpTransport.MAX_BYTES + 1)))
        }
    }

    @Test
    fun `public fetch rejects credentials authority and oversized requests before DNS`() {
        val client = BoundedHttpTransport(OutboundPolicy.Public)
        for (name in listOf("Authorization", "X-Internal-Token", "Cookie", "Proxy-Authorization", "Host")) {
            assertThrows(
                IllegalArgumentException::class.java,
            ) { client.execute(URI("https://invalid.example/"), headers = listOf(name to "fixture")) }
        }
        assertThrows(IllegalArgumentException::class.java) {
            client.execute(URI("https://invalid.example/"), body = ByteArray(BoundedHttpTransport.MAX_BYTES + 1))
        }
        assertThrows(IllegalArgumentException::class.java) { client.execute(URI("file:///etc/passwd")) }
        assertThrows(IllegalArgumentException::class.java) { client.execute(URI("http://169.254.169.254/latest/meta-data/")) }
    }

    @Test
    fun `resources permit local files and classpath without remote loaders`() {
        assertTrue(localResource("classpath:application.properties").exists())
        assertEquals("fixture", localResource("file:/tmp/fixture").filename)
        for (location in listOf(
            "https://invalid.example/x",
            "ftp://invalid.example/x",
            "file://server/share",
            "//server/share",
            "jar:https://invalid.example/x!/key",
        )) {
            assertThrows(IllegalArgumentException::class.java) { localResource(location) }
        }
    }
}
