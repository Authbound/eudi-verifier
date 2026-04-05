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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.tokenstatuslist

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.util.Base64
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.sdjwt.SdJwt
import eu.europa.ec.eudi.sdjwt.SdJwtAndKbJwt
import eu.europa.ec.eudi.sdjwt.SdJwtVcSpec
import eu.europa.ec.eudi.statium.BitsPerStatus
import eu.europa.ec.eudi.statium.PositiveDurationAsSeconds
import eu.europa.ec.eudi.statium.StatusList
import eu.europa.ec.eudi.statium.StatusListTokenClaims
import eu.europa.ec.eudi.statium.TokenStatusListSpec
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.CertOps
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.CertOps.toCertificate
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.ProvideTrustSource
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.X5CShouldBe
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.issuer.IssuerMetadataJwkSetResolver
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.issuer.IssuerMetadataTrustPolicy
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.jsonSupport
import eu.europa.ec.eudi.verifier.endpoint.domain.Clock
import eu.europa.ec.eudi.verifier.endpoint.domain.TransactionId
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
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.fail
import org.junit.jupiter.api.Test
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.io.ByteArrayOutputStream
import java.security.KeyPair
import java.security.cert.X509Certificate
import java.util.zip.DeflaterOutputStream
import kotlin.time.Duration.Companion.hours
import org.bouncycastle.asn1.x500.X500Name

class StatusListTokenValidatorTest {

    @Test
    fun `missing status list reference fails validation`() = runTest {
        val jwt = SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.ES256).build(),
            JWTClaimsSet.Builder()
                .claim(SdJwtVcSpec.VCT, "urn:example:vct")
                .build(),
        )
        val sdJwtAndKbJwt = SdJwtAndKbJwt(SdJwt(jwt, emptyList()), jwt)

        val validator = StatusListTokenValidator(
            httpClient = metadataHttpClient(emptyMap()),
            issuerMetadataJwkSetResolver = IssuerMetadataJwkSetResolver(
                metadataHttpClient(emptyMap()),
                IssuerMetadataTrustPolicy.Disabled,
            ),
            clock = Clock.System,
            publishPresentationEvent = PublishPresentationEvent { },
            provideTrustSource = ProvideTrustSource.forAll(X5CShouldBe.Ignored),
            cache = NoopStatusListTokenCache,
        )

        val error = try {
            validator.validate(sdJwtAndKbJwt, TransactionId("tx"))
            fail("Expected StatusCheckException")
        } catch (error: StatusCheckException) {
            error
        }

        assertEquals("Missing status_list reference in SD-JWT VC", error.reason)
    }

    @Test
    fun `status list token without x5c falls back to issuer metadata jwks`() = runTest {
        val issuer = "https://issuer.example/api/v1/openid4vci"
        val statusListUri = "$issuer/status-lists/pension"
        val signingKey = ECKeyGenerator(Curve.P_256)
            .keyUse(KeyUse.SIGNATURE)
            .keyID("issuer-key-1")
            .generate()
        val jwksJson = signingKey.toPublicJWK().toPublicJWKSetJson()
        val metadataJson =
            """
            {"issuer":"$issuer","jwks_uri":"https://issuer.example/public_keys.jwks"}
            """.trimIndent()
        val statusListJwt = buildStatusListToken(issuer, statusListUri, signingKey)

        val httpClient = metadataHttpClient(
            mapOf(
                "/.well-known/jwt-vc-issuer/api/v1/openid4vci" to metadataJson,
                "/public_keys.jwks" to jwksJson,
                "/api/v1/openid4vci/status-lists/pension" to statusListJwt,
            ),
        )
        val validator = StatusListTokenValidator(
            httpClient = httpClient,
            issuerMetadataJwkSetResolver = IssuerMetadataJwkSetResolver(
                httpClient,
                IssuerMetadataTrustPolicy(setOf(Regex("https://issuer\\.example/.*"))),
            ),
            clock = Clock.System,
            publishPresentationEvent = PublishPresentationEvent { },
            provideTrustSource = ProvideTrustSource.forAll(X5CShouldBe.Ignored),
            cache = NoopStatusListTokenCache,
        )

        val sdJwtAndKbJwt = credentialWithStatusReference(statusListUri)

        validator.validate(sdJwtAndKbJwt, TransactionId("tx"))
    }

    @Test
    fun `status list token with x5c stays valid when trust mode is ignored`() = runTest {
        val issuer = "https://issuer.example/api/v1/openid4vci"
        val statusListUri = "$issuer/status-lists/pension"
        val signingKey = ECKeyGenerator(Curve.P_256)
            .keyUse(KeyUse.SIGNATURE)
            .keyID("issuer-key-1")
            .generate()
        val signingKeyPair = KeyPair(signingKey.toECPublicKey(), signingKey.toECPrivateKey())
        val issuerCertHolder = CertOps.createTrustAnchor(
            keyPair = signingKeyPair,
            sigAlg = "SHA256withECDSA",
            name = X500Name("CN=Issuer"),
        )
        val statusListJwt = buildStatusListToken(
            issuer = issuer,
            statusListUri = statusListUri,
            signingKey = signingKeyPair,
            x5cCertificates = listOf(issuerCertHolder.toCertificate()),
        )
        val httpClient = metadataHttpClient(
            mapOf(
                "/api/v1/openid4vci/status-lists/pension" to statusListJwt,
            ),
        )
        val validator = StatusListTokenValidator(
            httpClient = httpClient,
            issuerMetadataJwkSetResolver = IssuerMetadataJwkSetResolver(
                metadataHttpClient(emptyMap()),
                IssuerMetadataTrustPolicy.Disabled,
            ),
            clock = Clock.System,
            publishPresentationEvent = PublishPresentationEvent { },
            provideTrustSource = ProvideTrustSource.forAll(X5CShouldBe.Ignored),
            cache = NoopStatusListTokenCache,
        )

        validator.validate(credentialWithStatusReference(statusListUri), TransactionId("tx"))
    }

    @Test
    fun `legacy current status checks bypass cached status list token`() = runTest {
        val issuer = "https://issuer.example/api/v1/openid4vci"
        val statusListUri = "$issuer/status-lists/pension"
        val signingKey = ECKeyGenerator(Curve.P_256)
            .keyUse(KeyUse.SIGNATURE)
            .keyID("issuer-key-1")
            .generate()
        val jwksJson = signingKey.toPublicJWK().toPublicJWKSetJson()
        val metadataJson =
            """
            {"issuer":"$issuer","jwks_uri":"https://issuer.example/public_keys.jwks"}
            """.trimIndent()
        val httpClient = metadataHttpClient(
            mapOf(
                "/.well-known/jwt-vc-issuer/api/v1/openid4vci" to metadataJson,
                "/public_keys.jwks" to jwksJson,
                "/api/v1/openid4vci/status-lists/pension" to buildStatusListToken(
                    issuer = issuer,
                    statusListUri = statusListUri,
                    signingKey = signingKey,
                    rawStatusList = byteArrayOf(0, 0, 0),
                ),
            ),
        )
        val staleClaims = StatusListTokenClaims(
            subject = statusListUri,
            issuedAt = Clock.System.now(),
            expirationTime = Clock.System.now().plus(1.hours),
            timeToLive = PositiveDurationAsSeconds(1.hours),
            statusList = StatusList.fromRawBytes(BitsPerStatus.One, byteArrayOf(0, 0)),
        )
        val validator = StatusListTokenValidator(
            httpClient = httpClient,
            issuerMetadataJwkSetResolver = IssuerMetadataJwkSetResolver(
                httpClient,
                IssuerMetadataTrustPolicy(setOf(Regex("https://issuer\\.example/.*"))),
            ),
            clock = Clock.System,
            publishPresentationEvent = PublishPresentationEvent { },
            provideTrustSource = ProvideTrustSource.forAll(X5CShouldBe.Ignored),
            cache = object : StatusListTokenCache {
                override suspend fun get(uri: String, at: kotlin.time.Instant?): StatusListTokenClaims? = staleClaims

                override suspend fun put(
                    uri: String,
                    at: kotlin.time.Instant?,
                    claims: StatusListTokenClaims,
                ) = Unit
            },
        )

        validator.validate(credentialWithStatusReference(statusListUri, index = 16), TransactionId("tx"))
    }

    @Test
    fun `versioned current status checks reuse cached status list token`() = runTest {
        val issuer = "https://issuer.example/api/v1/openid4vci"
        val statusListUri = "$issuer/status-lists/pension/versions/0"
        var cacheGetCalls = 0
        var cachePutCalls = 0
        val cachedClaims = StatusListTokenClaims(
            subject = statusListUri,
            issuedAt = Clock.System.now(),
            expirationTime = Clock.System.now().plus(1.hours),
            timeToLive = PositiveDurationAsSeconds(1.hours),
            statusList = StatusList.fromRawBytes(BitsPerStatus.One, byteArrayOf(0, 0, 0)),
        )
        val validator = StatusListTokenValidator(
            httpClient = metadataHttpClient(emptyMap()),
            issuerMetadataJwkSetResolver = IssuerMetadataJwkSetResolver(
                metadataHttpClient(emptyMap()),
                IssuerMetadataTrustPolicy.Disabled,
            ),
            clock = Clock.System,
            publishPresentationEvent = PublishPresentationEvent { },
            provideTrustSource = ProvideTrustSource.forAll(X5CShouldBe.Ignored),
            cache = object : StatusListTokenCache {
                override suspend fun get(uri: String, at: kotlin.time.Instant?): StatusListTokenClaims? {
                    cacheGetCalls += 1
                    return cachedClaims
                }

                override suspend fun put(
                    uri: String,
                    at: kotlin.time.Instant?,
                    claims: StatusListTokenClaims,
                ) {
                    cachePutCalls += 1
                }
            },
        )

        validator.validate(credentialWithStatusReference(statusListUri, index = 16), TransactionId("tx"))

        assertEquals(1, cacheGetCalls)
        assertEquals(0, cachePutCalls)
    }
}

private fun credentialWithStatusReference(statusListUri: String, index: Int = 0): SdJwtAndKbJwt<SignedJWT> {
    val jwt = SignedJWT(
        JWSHeader.Builder(JWSAlgorithm.ES256).build(),
        JWTClaimsSet.Builder()
            .claim(SdJwtVcSpec.VCT, "urn:example:vct")
            .claim(
                TokenStatusListSpec.STATUS,
                mapOf(
                    TokenStatusListSpec.STATUS_LIST to mapOf(
                        TokenStatusListSpec.IDX to index,
                        TokenStatusListSpec.URI to statusListUri,
                    ),
                ),
            )
            .build(),
    )
    return SdJwtAndKbJwt(SdJwt(jwt, emptyList()), jwt)
}

private fun metadataHttpClient(paths: Map<String, String>): HttpClient =
    HttpClient(
        MockEngine { request ->
            val body = paths[request.url.fullPath] ?: error("Unexpected request ${request.url}")
            respond(
                content = body,
                status = HttpStatusCode.OK,
                headers = io.ktor.http.headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString()),
            )
        },
    ) {
        install(ContentNegotiation) {
            json(jsonSupport)
        }
    }

private fun buildStatusListToken(
    issuer: String,
    statusListUri: String,
    signingKey: com.nimbusds.jose.jwk.ECKey,
    x5cCertificates: List<X509Certificate> = emptyList(),
    rawStatusList: ByteArray = byteArrayOf(0),
): String {
    val issuedAt = Instant.now().minusSeconds(30)
    val expiresAt = issuedAt.plus(1, ChronoUnit.HOURS)
    val claims = JWTClaimsSet.Builder()
        .issuer(issuer)
        .subject(statusListUri)
        .issueTime(java.util.Date.from(issuedAt))
        .expirationTime(java.util.Date.from(expiresAt))
        .claim(TokenStatusListSpec.TIME_TO_LIVE, 3600)
        .claim(
            TokenStatusListSpec.STATUS_LIST,
            mapOf<String, Any>(
                TokenStatusListSpec.BITS to 1,
                TokenStatusListSpec.LIST to encodeStatusList(rawStatusList),
            ) as Any,
        )
        .build()

    val jwt = SignedJWT(
        JWSHeader.Builder(JWSAlgorithm.ES256)
            .keyID(signingKey.keyID)
            .type(JOSEObjectType(TokenStatusListSpec.MEDIA_SUBTYPE_STATUS_LIST_JWT))
            .apply {
                if (x5cCertificates.isNotEmpty()) {
                    x509CertChain(x5cCertificates.map { Base64.encode(it.encoded) })
                }
            }
            .build(),
        claims,
    )
    jwt.sign(ECDSASigner(signingKey))
    return jwt.serialize()
}

private fun buildStatusListToken(
    issuer: String,
    statusListUri: String,
    signingKey: KeyPair,
    x5cCertificates: List<X509Certificate> = emptyList(),
    rawStatusList: ByteArray = byteArrayOf(0),
): String {
    val issuedAt = Instant.now().minusSeconds(30)
    val expiresAt = issuedAt.plus(1, ChronoUnit.HOURS)
    val claims = JWTClaimsSet.Builder()
        .issuer(issuer)
        .subject(statusListUri)
        .issueTime(java.util.Date.from(issuedAt))
        .expirationTime(java.util.Date.from(expiresAt))
        .claim(TokenStatusListSpec.TIME_TO_LIVE, 3600)
        .claim(
            TokenStatusListSpec.STATUS_LIST,
            mapOf<String, Any>(
                TokenStatusListSpec.BITS to 1,
                TokenStatusListSpec.LIST to encodeStatusList(rawStatusList),
            ) as Any,
        )
        .build()

    val jwt = SignedJWT(
        JWSHeader.Builder(JWSAlgorithm.ES256)
            .keyID("issuer-key-1")
            .type(JOSEObjectType(TokenStatusListSpec.MEDIA_SUBTYPE_STATUS_LIST_JWT))
            .apply {
                if (x5cCertificates.isNotEmpty()) {
                    x509CertChain(x5cCertificates.map { Base64.encode(it.encoded) })
                }
            }
            .build(),
        claims,
    )
    jwt.sign(ECDSASigner(signingKey.private as java.security.interfaces.ECPrivateKey))
    return jwt.serialize()
}

private fun com.nimbusds.jose.jwk.JWK.toPublicJWKSetJson(): String =
    com.nimbusds.jose.jwk.JWKSet(toPublicJWK()).toString(false)

private fun encodeStatusList(rawStatusList: ByteArray): String {
    val output = ByteArrayOutputStream()
    DeflaterOutputStream(output).use { it.write(rawStatusList) }
    return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(output.toByteArray())
}
