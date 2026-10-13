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

import java.net.InetAddress
import java.net.URI

/** Destination authority is separate from cryptographic issuer trust. */
class OutboundPolicy private constructor(private val exact: URI?, private val method: String, private val privateNetwork: Boolean) {
    fun bind(uri: URI, requestMethod: String, lookup: (String) -> Array<InetAddress>): BoundDestination {
        require(requestMethod == method) { "Outbound method is not authorized" }
        require(uri.userInfo == null && uri.fragment == null && !uri.host.isNullOrBlank()) { "Invalid outbound authority" }
        require(uri.host.all { it.code < 128 } && !uri.host.endsWith('.')) { "Noncanonical outbound host" }
        if (exact == null) {
            require(uri.scheme == "https" && uri.port in listOf(-1, 443)) { "Public outbound requests require HTTPS on port 443" }
            require(
                uri.host.lowercase() !in setOf("localhost", "localhost.localdomain") && !uri.host.endsWith(".localhost"),
            ) { "Local outbound host" }
        } else {
            require(uri == exact) { "Outbound URI is outside the configured exact endpoint" }
        }
        val addresses = lookup(uri.host)
        require(addresses.isNotEmpty() && addresses.all { if (privateNetwork) isPrivate(it) else isGlobal(it) }) {
            "Outbound DNS answer includes a disallowed address"
        }
        return BoundDestination(uri.host, addresses.copyOf())
    }

    companion object {
        val Public = OutboundPolicy(null, "GET", false)

        fun exactInternal(uri: URI, method: String): OutboundPolicy {
            require(
                uri.scheme in setOf("http", "https") && uri.userInfo == null && uri.fragment == null &&
                    uri.query == null && !uri.host.isNullOrBlank(),
            )
            require(uri.host in setOf("pension-backend", "gateway")) { "Unapproved internal service" }
            val supported = (
                uri.scheme == "http" && uri.host == "pension-backend" && uri.port == 3010 &&
                    uri.rawPath == "/internal/eudi-verifier/presentations/wallet-response" && method == "POST"
                ) ||
                (
                    uri.scheme == "http" && uri.host == "gateway" && uri.port == 8080 &&
                        uri.rawPath == "/.well-known/eudi-s2s-jwks.json" && method == "GET"
                    )
            require(supported) { "Internal endpoint is not an approved pension contract" }
            return OutboundPolicy(uri, method, true)
        }

        fun exactPublic(uri: URI, method: String): OutboundPolicy {
            require(
                uri.scheme == "https" && uri.port in listOf(-1, 443) && uri.userInfo == null && uri.fragment == null &&
                    uri.query == null && !uri.host.isNullOrBlank(),
            )
            return OutboundPolicy(uri, method, false)
        }

        private fun isPrivate(address: InetAddress): Boolean {
            val b = address.address.map { it.toInt() and 255 }
            return when (b.size) {
                4 -> b[0] == 10 || (b[0] == 172 && b[1] in 16..31) || (b[0] == 192 && b[1] == 168)
                16 -> (b[0] and 254) == 252 && !(b[0] == 253 && b[1] == 0 && b[2] == 14 && b[3] == 194)
                else -> false
            }
        }

        private fun isGlobal(address: InetAddress): Boolean {
            val b = address.address.map { it.toInt() and 255 }
            if (
                address.isAnyLocalAddress || address.isLoopbackAddress || address.isLinkLocalAddress ||
                address.isSiteLocalAddress || address.isMulticastAddress
            ) return false
            return when (b.size) {
                4 -> !(
                    b[0] == 0 || b[0] == 10 || b[0] == 127 || b[0] >= 224 ||
                        (b[0] == 100 && b[1] in 64..127) || (b[0] == 169 && b[1] == 254) ||
                        (b[0] == 172 && b[1] in 16..31) || (b[0] == 192 && (b[1] == 168 || b[1] == 0 || (b[1] == 88 && b[2] == 99))) ||
                        (b[0] == 198 && (b[1] in 18..19 || (b[1] == 51 && b[2] == 100))) ||
                        (b[0] == 203 && b[1] == 0 && b[2] == 113)
                    )
                16 -> (b[0] and 224) == 32 &&
                    !(b[0] == 32 && b[1] == 1 && (b[2] <= 1 || (b[2] == 13 && b[3] == 184))) &&
                    !(b[0] == 32 && b[1] == 2) && !(b[0] == 63 && (b[1] and 240) == 240)
                else -> false
            }
        }
    }
}

class BoundDestination internal constructor(val host: String, private val addresses: Array<InetAddress>) {
    /** The dialer receives exactly the validated answer set, never a second DNS lookup. */
    fun resolve(requestedHost: String): Array<InetAddress> {
        require(requestedHost.equals(host, ignoreCase = true)) { "Connection authority differs from bound destination" }
        return addresses.copyOf()
    }
}
