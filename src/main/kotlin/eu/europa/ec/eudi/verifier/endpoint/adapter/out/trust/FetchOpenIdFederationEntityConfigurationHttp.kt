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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.trust

import arrow.core.Either
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.FetchOpenIdFederationEntityConfiguration
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.OpenIdFederationEntityConfiguration
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.net.InetAddress
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

class FetchOpenIdFederationEntityConfigurationHttp(
    private val httpClient: HttpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(5))
        .build(),
) : FetchOpenIdFederationEntityConfiguration {

    override fun invoke(entityId: String): Either<Throwable, OpenIdFederationEntityConfiguration> =
        Either.catch {
            val wellKnown = openIdFederationWellKnownUri(entityId)
            val request = HttpRequest.newBuilder(wellKnown)
                .timeout(Duration.ofSeconds(10))
                .GET()
                .build()
            val response = httpClient.send(request, HttpResponse.BodyHandlers.ofString())
            require(response.statusCode() in 200..299) {
                "OpenID Federation entity configuration returned HTTP ${response.statusCode()}"
            }
            parseEntityConfigurationResponse(response.body())
        }

    private fun parseEntityConfigurationResponse(responseBody: String): OpenIdFederationEntityConfiguration {
        val trimmed = responseBody.trim()
        return if (trimmed.startsWith("{")) {
            val jsonObject = json.parseToJsonElement(trimmed).jsonObject
            jsonObject["entity_configuration"]
                ?.jsonPrimitive
                ?.contentOrNull
                ?.let(::parseEntityStatementJwt)
                ?: jsonObject.toEntityConfiguration()
        } else {
            parseEntityStatementJwt(trimmed)
        }
    }

    private fun openIdFederationWellKnownUri(entityId: String): URI {
        val entityUri = URI(entityId.removeSuffix("/"))
        require(entityUri.scheme == "https") { "OpenID Federation entity id must use https" }
        require(entityUri.userInfo == null) { "OpenID Federation entity id must not include userinfo" }
        require(!entityUri.host.isNullOrBlank()) { "OpenID Federation entity id must include a host" }
        require(InetAddress.getAllByName(entityUri.host).none(InetAddress::isLocalAddress)) {
            "OpenID Federation entity id must not resolve to a local address"
        }
        return URI("${entityUri.toASCIIString()}/.well-known/openid-federation")
    }

    private fun parseEntityStatementJwt(jwt: String): OpenIdFederationEntityConfiguration {
        val claims = SignedJWT.parse(jwt).jwtClaimsSet
        return OpenIdFederationEntityConfiguration(
            sub = claims.subject,
            authorityHints = claims.getStringListClaim("authority_hints").orEmpty(),
        )
    }

    private fun JsonObject.toEntityConfiguration(): OpenIdFederationEntityConfiguration =
        OpenIdFederationEntityConfiguration(
            sub = this["sub"]?.jsonPrimitive?.contentOrNull,
            authorityHints = this["authority_hints"]
                ?.jsonArray
                ?.mapNotNull { it.jsonPrimitive.contentOrNull }
                .orEmpty(),
        )

    companion object {
        private val json = Json { ignoreUnknownKeys = true }
    }
}

private fun InetAddress.isLocalAddress(): Boolean =
    isAnyLocalAddress || isLoopbackAddress || isLinkLocalAddress || isSiteLocalAddress || isMulticastAddress
