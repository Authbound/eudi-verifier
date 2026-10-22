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

import eu.europa.ec.eudi.verifier.endpoint.adapter.out.http.OutboundPolicy
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.springframework.mock.env.MockEnvironment
import java.net.InetAddress
import java.net.URI

class LocalWalletNetworkTest {
    private val origin = URI("https://localhost:54471")
    private val target = URI("https://localhost:54471/api/v1/openid4vci/jwks.json")
    private val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
    private val publicAddress = InetAddress.getByAddress(byteArrayOf(8, 8, 8, 8))

    private fun environment() = MockEnvironment()
        .withProperty("server.address", "127.0.0.1")
        .withProperty("verifier.localWallet.allowedOrigins", origin.toString())
        .apply { setActiveProfiles("local-wallet") }

    @Test
    fun `default and production configurations never enable loopback`() {
        assertTrue(localWalletOrigins(MockEnvironment()).isEmpty())
        for (profiles in listOf(arrayOf("production", "local-wallet"), arrayOf("prod", "local-wallet"), arrayOf("kms-x509-hash", "local-wallet"), arrayOf("kms-san-dns", "local-wallet"), arrayOf("dev"))) {
            val env = environment().apply { setActiveProfiles(*profiles) }
            assertThrows(IllegalArgumentException::class.java) { localWalletOrigins(env) }
        }
        assertThrows(IllegalArgumentException::class.java) {
            OutboundPolicy.Public.bind(target, "GET") { arrayOf(loopback) }
        }
        assertThrows(IllegalArgumentException::class.java) { OutboundPolicy.exactPublic(target, "GET") }
    }

    @Test
    fun `local profile requires a loopback listener and explicit TLS origins`() {
        assertThrows(IllegalArgumentException::class.java) {
            localWalletOrigins(environment().withProperty("server.address", "0.0.0.0"))
        }
        for (invalid in listOf(
            "http://localhost:54471",
            "https://example.com",
            "https://localhost:54471/private",
            "https://user@localhost:54471",
        )) {
            assertThrows(IllegalArgumentException::class.java) {
                localWalletOrigins(environment().withProperty("verifier.localWallet.allowedOrigins", invalid))
            }
        }
        assertEquals(setOf(origin), localWalletOrigins(environment()))
    }

    @Test
    fun `local metadata is bound to the exact approved TLS authority and loopback DNS`() {
        val policy = OutboundPolicy.localWallet(localWalletOrigins(environment()))
        val bound = policy.bind(target, "GET") { arrayOf(loopback) }
        assertArrayEquals(arrayOf(loopback), bound.resolve("localhost"))
        for (uri in listOf(URI("https://localhost:54472/keys"), URI("http://localhost:54471/keys"), URI("https://127.0.0.1:54471/keys"))) {
            assertThrows(IllegalArgumentException::class.java) { policy.bind(uri, "GET") { arrayOf(loopback) } }
        }
        assertThrows(IllegalArgumentException::class.java) { policy.bind(target, "POST") { arrayOf(loopback) } }
        assertThrows(IllegalArgumentException::class.java) { policy.bind(target, "GET") { arrayOf(loopback, publicAddress) } }
        assertThrows(IllegalArgumentException::class.java) { policy.bind(target, "GET") { arrayOf(publicAddress) } }
        val publicTarget = URI("https://issuer.example/keys")
        assertArrayEquals(arrayOf(publicAddress), policy.bind(publicTarget, "GET") { arrayOf(publicAddress) }.resolve("issuer.example"))
    }

    @Test
    fun `service key retrieval stays bound to its one configured endpoint`() {
        val policy = OutboundPolicy.exactPublic(target, "GET", localWalletOrigins(environment()))
        policy.bind(target, "GET") { arrayOf(loopback) }
        assertThrows(IllegalArgumentException::class.java) {
            policy.bind(URI("https://localhost:54471/other"), "GET") { arrayOf(loopback) }
        }
    }

    @Test
    fun `local callback permits only its exact TLS endpoint and loopback DNS`() {
        val callback = URI("https://localhost:54471/internal/eudi-verifier/presentations/wallet-response")
        val origins = localWalletOrigins(environment())
        val policy = OutboundPolicy.exactInternal(callback, "POST", origins)
        policy.bind(callback, "POST") { arrayOf(loopback) }
        assertThrows(IllegalArgumentException::class.java) { OutboundPolicy.exactInternal(callback, "POST") }
        assertThrows(IllegalArgumentException::class.java) { OutboundPolicy.exactInternal(target, "POST", origins) }
        assertThrows(IllegalArgumentException::class.java) { OutboundPolicy.exactInternal(callback, "GET", origins) }
        assertThrows(IllegalArgumentException::class.java) { policy.bind(target, "POST") { arrayOf(loopback) } }
        assertThrows(IllegalArgumentException::class.java) { policy.bind(callback, "GET") { arrayOf(loopback) } }
        assertThrows(IllegalArgumentException::class.java) { policy.bind(callback, "POST") { arrayOf(loopback, publicAddress) } }
    }
}
