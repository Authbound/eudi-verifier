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
// Modifications Copyright (c) 2026 Authbound
package eu.europa.ec.eudi.verifier.endpoint.adapter.input.web

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.sdjwt.vc.TypeMetadataPolicy
import eu.europa.ec.eudi.verifier.endpoint.TestContext
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.ProvideTrustSource
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.issuer.IssuerMetadataJwkSetResolver
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.issuer.IssuerMetadataTrustPolicy
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.jsonSupport
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.sdjwtvc.SdJwtVcValidator
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.tokenstatuslist.StatusListTokenValidator
import eu.europa.ec.eudi.verifier.endpoint.domain.Clock
import eu.europa.ec.eudi.verifier.endpoint.port.input.ProcessSdJwtVc
import eu.europa.ec.eudi.verifier.endpoint.port.input.ValidateMsoMdocDeviceResponse
import eu.europa.ec.eudi.verifier.endpoint.port.input.ValidateSdJwtVc
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PublishPresentationEvent
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.fullPath
import io.ktor.serialization.kotlinx.json.json
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import org.mockito.Mockito.mock
import org.springframework.http.MediaType
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.util.LinkedMultiValueMap
import org.springframework.web.reactive.function.BodyInserters
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.time.Instant
import java.util.Date
import java.util.zip.DeflaterOutputStream
import kotlin.time.Duration.Companion.seconds

internal class UtilityRequiredStatusTest {
    private val issuer = "https://issuer.example/api/v1/openid4vci"
    private val statusUri = "$issuer/status-lists/badge"
    private val issuerKey = ECKeyGenerator(Curve.P_256).keyID("issuer-1").generate()
    private val holderKey = ECKeyGenerator(Curve.P_256).generate()
    private val now = Instant.now()
    private val nonce = "synthetic-request-nonce"
    private val header = "Authbound-Status-Validation"

    @Test
    fun `required active status returns verified claims and confirmation`() {
        post(client(), credential()).expectStatus().isOk
            .expectHeader().valueEquals(header, "valid")
            .expectBody().jsonPath("$.name").isEqualTo("Ada Lovelace")
    }

    @ParameterizedTest
    @ValueSource(strings = ["revoked", "expired", "bad-signature", "unavailable"])
    fun `invalid or unavailable status never gets confirmation`(status: String) {
        post(client(status = status), credential()).expectStatus().isBadRequest
            .expectHeader().doesNotExist(header)
            .expectBody().jsonPath("$[0].error").isEqualTo("StatusCheckFailed")
    }

    @Test
    fun `required status cannot succeed when validator is disabled`() {
        post(client(enabled = false), credential()).expectStatus().isBadRequest
            .expectHeader().doesNotExist(header)
            .expectBody().jsonPath("$[0].error").isEqualTo("StatusCheckFailed")
    }

    @Test
    fun `required status rejects a credential without a reference`() {
        post(client(), credential(withStatus = false)).expectStatus().isBadRequest
            .expectHeader().doesNotExist(header)
    }

    @ParameterizedTest
    @ValueSource(strings = ["nonce", "audience", "holder", "disclosure", "issuer", "kb-iat-past", "kb-iat-future"])
    fun `status success cannot hide invalid credential or holder proof`(fault: String) {
        post(client(), credential(fault = fault)).expectStatus().isBadRequest
            .expectHeader().doesNotExist(header)
    }

    @Test
    fun `a credential with an invalid issuer signature never triggers a status list fetch`() {
        val requested = mutableListOf<String>()
        post(client(requested = requested), credential(fault = "issuer")).expectStatus().isBadRequest
            .expectHeader().doesNotExist(header)
        assertTrue(requested.none { it.contains("status-lists") }, "status list fetched for an unverified credential: $requested")
    }

    @ParameterizedTest
    @ValueSource(strings = ["false", "absent"])
    fun `optional callers never receive required status confirmation`(flag: String) {
        post(client(), credential(), if (flag == "absent") emptyList() else listOf(flag))
            .expectStatus().isOk.expectHeader().doesNotExist(header)
    }

    @ParameterizedTest
    @ValueSource(strings = ["TRUE", "", "yes", "true,false"])
    fun `malformed or duplicate status flag is rejected`(flag: String) {
        post(client(), credential(), flag.split(",")).expectStatus().isBadRequest
            .expectHeader().doesNotExist(header)
    }

    private fun post(client: WebTestClient, token: String, flag: List<String> = listOf("true")): WebTestClient.ResponseSpec {
        val form = LinkedMultiValueMap<String, String>()
        form.add("sd_jwt_vc", token)
        form.add("nonce", nonce)
        flag.forEach { form.add("require_status", it) }
        return client.post().uri(UtilityApi.VALIDATE_SD_JWT_VC_PATH)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .accept(MediaType.APPLICATION_JSON).body(BodyInserters.fromFormData(form)).exchange()
    }

    private fun client(
        enabled: Boolean = true,
        status: String = "active",
        requested: MutableList<String> = mutableListOf(),
    ): WebTestClient {
        val http = HttpClient(
            MockEngine { request ->
                val path = request.url.fullPath
                requested += path
                val body = when (path) {
                    "/.well-known/jwt-vc-issuer/api/v1/openid4vci" ->
                        """{"issuer":"$issuer","jwks_uri":"https://issuer.example/jwks"}"""
                    "/jwks" -> JWKSet(issuerKey.toPublicJWK()).toString(false)
                    "/api/v1/openid4vci/status-lists/badge" -> statusToken(status)
                    else -> error("Unexpected synthetic issuer request: $path")
                }
                respond(
                    body,
                    if (status == "unavailable" && path.contains("status-lists")) HttpStatusCode.ServiceUnavailable else HttpStatusCode.OK,
                    io.ktor.http.headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString()),
                )
            },
        ) { install(ContentNegotiation) { json(jsonSupport) } }
        val trust = ProvideTrustSource { null }
        val policy = IssuerMetadataTrustPolicy(setOf(Regex("https://issuer\\.example/.*")))
        val statusValidator = if (enabled) StatusListTokenValidator(
            http,
            IssuerMetadataJwkSetResolver(http, policy),
            Clock.System,
            PublishPresentationEvent { },
            trust,
        ) else null
        val validator = SdJwtVcValidator(
            trust,
            http,
            policy,
            TestContext.verifierId,
            statusValidator,
            clock = Clock.System,
            skew = 5.seconds,
            typeMetadataPolicy = TypeMetadataPolicy.NotUsed,
        )
        val validate = ValidateSdJwtVc({ validator }, { error("No synthetic certificate chain expected") })
        return WebTestClient.bindToRouterFunction(
            UtilityApi(mock(ValidateMsoMdocDeviceResponse::class.java), validate, ProcessSdJwtVc()).route,
        ).build()
    }

    private fun signed(claims: JWTClaimsSet, type: String, key: ECKey): String = SignedJWT(
        JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType(type)).keyID(key.keyID).build(),
        claims,
    ).apply { sign(ECDSASigner(key)) }.serialize()

    private fun digest(value: String) = Base64URL.encode(MessageDigest.getInstance("SHA-256").digest(value.toByteArray())).toString()

    private fun credential(withStatus: Boolean = true, fault: String = ""): String {
        val disclosure = Base64URL.encode("""["synthetic-salt","name","Ada Lovelace"]""").toString()
        val claims = JWTClaimsSet.Builder().issuer(issuer).issueTime(Date.from(now.minusSeconds(30)))
            .notBeforeTime(Date.from(now.minusSeconds(30))).expirationTime(Date.from(now.plusSeconds(3600)))
            .claim("vct", "urn:vc:authbound:employee-badge:1").claim("_sd_alg", "sha-256")
            .claim("_sd", listOf(digest(disclosure))).claim("company", "ACME").claim("job_role", "Engineer")
            .claim("cnf", mapOf("jwk" to holderKey.toPublicJWK().toJSONObject()))
        if (withStatus) claims.claim("status", mapOf("status_list" to mapOf("uri" to statusUri, "idx" to 0)))
        var issuerJwt = signed(claims.build(), "dc+sd-jwt", issuerKey)
        if (fault == "issuer") {
            val parts = issuerJwt.split(".")
            issuerJwt = parts[0] + "." + parts[1] + "." + (if (parts[2][0] == 'A') "B" else "A") + parts[2].substring(1)
        }
        val presentation = "$issuerJwt~$disclosure~"
        val kb = JWTClaimsSet.Builder().audience(if (fault == "audience") "wrong-audience" else TestContext.verifierId.clientId)
            .issueTime(Date.from(kbIssuedAt(fault))).claim("nonce", if (fault == "nonce") "wrong-nonce" else nonce)
            .claim("sd_hash", digest(presentation)).build()
        val key = if (fault == "holder") ECKeyGenerator(Curve.P_256).generate() else holderKey
        val token = presentation + signed(kb, "kb+jwt", key)
        return if (fault == "disclosure") token.replace(
            disclosure,
            Base64URL.encode("""["synthetic-salt","name","Mallory"]""").toString(),
        ) else token
    }

    // The verifier accepts a KB-JWT `iat` only within the configured skew (PT5S) of validation time.
    private fun kbIssuedAt(fault: String): Instant = when (fault) {
        "kb-iat-past" -> now.minusSeconds(60)
        "kb-iat-future" -> now.plusSeconds(60)
        else -> now
    }

    private fun statusToken(status: String): String {
        val compressed = ByteArrayOutputStream()
        DeflaterOutputStream(compressed).use { it.write(byteArrayOf(if (status == "revoked") 1 else 0)) }
        val claims = JWTClaimsSet.Builder().issuer(issuer).subject(statusUri)
            .issueTime(Date.from(now.minusSeconds(if (status == "expired") 7200 else 30)))
            .expirationTime(Date.from(now.plusSeconds(if (status == "expired") -3600 else 3600)))
            .claim(
                "ttl",
                3600,
            ).claim("status_list", mapOf("bits" to 1, "lst" to Base64URL.encode(compressed.toByteArray()).toString())).build()
        return signed(claims, "statuslist+jwt", if (status == "bad-signature") ECKeyGenerator(Curve.P_256).generate() else issuerKey)
    }
}
