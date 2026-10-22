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
import java.net.InetAddress
import java.net.URI

class OutboundPolicyTest {
    private fun ip(vararg bytes: Int) = InetAddress.getByAddress(bytes.map { it.toByte() }.toByteArray())

    @Test
    fun `public policy rejects non global answers including mixed DNS`() {
        val denied =
            listOf(
                ip(
                    0,
                    1,
                    2,
                    3,
                ),
                ip(
                    10,
                    1,
                    2,
                    3,
                ),
                ip(
                    100,
                    64,
                    0,
                    1,
                ),
                ip(
                    127,
                    0,
                    0,
                    1,
                ),
                ip(
                    169,
                    254,
                    169,
                    254,
                ),
                ip(
                    172,
                    16,
                    0,
                    1,
                ),
                ip(
                    192,
                    0,
                    0,
                    9,
                ),
                ip(
                    192,
                    0,
                    2,
                    1,
                ),
                ip(192, 168, 1, 1), ip(198, 18, 0, 1), ip(198, 51, 100, 1), ip(203, 0, 113, 1), ip(224, 1, 1, 1), ip(240, 1, 1, 1),
            )
        for (address in denied) {
            assertThrows(IllegalArgumentException::class.java) {
                OutboundPolicy.Public.bind(URI("https://issuer.example/keys"), "GET") { arrayOf(address) }
            }
            assertThrows(IllegalArgumentException::class.java) {
                OutboundPolicy.Public.bind(URI("https://issuer.example/keys"), "GET") { arrayOf(ip(8, 8, 8, 8), address) }
            }
        }
    }

    @Test
    fun `public destination is bound once without widening internal policy`() {
        var calls = 0
        val bound = OutboundPolicy.Public.bind(URI("https://issuer.example/keys"), "GET") {
            calls++
            arrayOf(ip(8, 8, 8, 8))
        }
        assertEquals(1, calls)
        assertEquals("issuer.example", bound.host)
        assertArrayEquals(arrayOf(ip(8, 8, 8, 8)), bound.resolve("issuer.example"))
        assertEquals(1, calls)
        assertThrows(IllegalArgumentException::class.java) { bound.resolve("other.example") }
    }

    @Test
    fun `public URL and methods fail closed`() {
        for (url in listOf(
            "http://issuer.example/keys",
            "https://user:pass@issuer.example/keys",
            "https://issuer.example:444/keys",
            "https://issuer.example/keys#fragment",
            "https://localhost/keys",
        )) {
            assertThrows(IllegalArgumentException::class.java) { OutboundPolicy.Public.bind(URI(url), "GET") { arrayOf(ip(8, 8, 8, 8)) } }
        }
        assertThrows(IllegalArgumentException::class.java) {
            OutboundPolicy.Public.bind(URI("https://issuer.example/keys"), "POST") { arrayOf(ip(8, 8, 8, 8)) }
        }
    }

    @Test
    fun `internal exception is exact origin path method and private address`() {
        val policy = OutboundPolicy.exactInternal(
            URI("http://pension-backend:3010/internal/eudi-verifier/presentations/wallet-response"),
            "POST",
        )
        policy.bind(
            URI("http://pension-backend:3010/internal/eudi-verifier/presentations/wallet-response"),
            "POST",
        ) { arrayOf(ip(172, 20, 0, 2)) }
        for (url in listOf(
            "http://pension-backend:3010/other",
            "http://other:3010/internal/eudi-verifier/presentations/wallet-response",
            "http://pension-backend:3010/internal/eudi-verifier/presentations/wallet-response?redirect=x",
        )) {
            assertThrows(IllegalArgumentException::class.java) { policy.bind(URI(url), "POST") { arrayOf(ip(172, 20, 0, 2)) } }
        }
        for (address in listOf(ip(127, 0, 0, 1), ip(169, 254, 169, 254), ip(8, 8, 8, 8))) {
            assertThrows(IllegalArgumentException::class.java) {
                policy.bind(
                    URI("http://pension-backend:3010/internal/eudi-verifier/presentations/wallet-response"),
                    "POST",
                ) { arrayOf(address) }
            }
        }
    }

    @Test
    fun `IPv6 public ranges reject special prefixes`() {
        for (address in listOf("::1", "fc00::1", "fe80::1", "2001:db8::1", "2001::1", "2002::1", "3fff::1")) {
            assertThrows(IllegalArgumentException::class.java) {
                OutboundPolicy.Public.bind(URI("https://issuer.example/keys"), "GET") { arrayOf(InetAddress.getByName(address)) }
            }
        }
        OutboundPolicy.Public.bind(URI("https://issuer.example/keys"), "GET") { arrayOf(InetAddress.getByName("2606:4700:4700::1111")) }
    }
}
