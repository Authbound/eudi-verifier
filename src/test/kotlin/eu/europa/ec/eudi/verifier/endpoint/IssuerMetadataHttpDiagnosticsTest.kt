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
package eu.europa.ec.eudi.verifier.endpoint

import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.read.ListAppender
import com.sun.net.httpserver.HttpServer
import io.ktor.client.HttpClient
import io.ktor.client.plugins.ServerResponseException
import io.ktor.client.request.get
import kotlinx.coroutines.runBlocking
import org.slf4j.LoggerFactory
import java.net.InetSocketAddress
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class IssuerMetadataHttpDiagnosticsTest {
    @Test
    fun `metadata failures preserve exceptions and omit sensitive data`() = runBlocking {
        val marker = "private-query-and-body-marker"
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.createContext("/") { exchange ->
            val body = marker.toByteArray()
            exchange.sendResponseHeaders(503, body.size.toLong())
            exchange.responseBody.use { it.write(body) }
        }
        server.start()
        val logger = LoggerFactory.getLogger(VerifierApplication::class.java) as Logger
        val events = ListAppender<ILoggingEvent>().apply { start() }
        logger.addAppender(events)
        val factory = Class.forName("eu.europa.ec.eudi.verifier.endpoint.VerifierContextKt")
            .declaredMethods.single { it.name == "createHttpClient" }
            .apply { isAccessible = true }
        val client = factory.invoke(null, true, false, null) as HttpClient
        val origin = "http://127.0.0.1:${server.address.port}"
        try {
            assertFailsWith<ServerResponseException> {
                client.get("$origin/.well-known/jwt-vc-issuer/issuer?secret=$marker")
            }
            assertTrue(events.list.single().formattedMessage.contains("status=503"))
            assertFalse(events.list.single().formattedMessage.contains(marker))
            assertEquals(null, events.list.single().throwableProxy)
            events.list.clear()
            assertFailsWith<ServerResponseException> { client.get("$origin/other?secret=$marker") }
            assertTrue(events.list.isEmpty())
            server.stop(0)
            assertFails { client.get("$origin/issuer/.well-known/jwt-vc-issuer?secret=$marker") }
            assertTrue(events.list.isNotEmpty())
            assertTrue(events.list.all { it.formattedMessage.contains("exceptionType=") })
            assertTrue(events.list.none { it.formattedMessage.contains(marker) || it.throwableProxy != null })
        } finally {
            client.close()
            server.stop(0)
            logger.detachAppender(events)
            events.stop()
        }
    }
}
