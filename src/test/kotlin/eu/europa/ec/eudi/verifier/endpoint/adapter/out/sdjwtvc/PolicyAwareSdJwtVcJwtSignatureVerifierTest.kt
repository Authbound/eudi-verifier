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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.sdjwtvc

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import eu.europa.ec.eudi.sdjwt.SdJwtVerificationException
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.CertOps
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.CertOps.toCertificate
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.ProvideTrustSource
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.X5CShouldBe
import eu.europa.ec.eudi.sdjwt.vc.X509CertificateTrust
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.issuer.IssuerMetadataJwkSetResolver
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.issuer.IssuerMetadataTrustPolicy
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.jsonSupport
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
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.bouncycastle.asn1.x500.X500Name

class PolicyAwareSdJwtVcJwtSignatureVerifierTest {

    @Test
    fun `verifies sd-jwt vc using issuer metadata jwks when issuer is allowlisted`() = runTest {
        val issuer = "https://issuer.example/api/v1/openid4vci"
        val signingKey = ECKeyGenerator(Curve.P_256)
            .keyUse(KeyUse.SIGNATURE)
            .keyID("issuer-key-1")
            .generate()
        val metadataJson =
            """
            {"issuer":"$issuer","jwks_uri":"https://issuer.example/public_keys.jwks"}
            """.trimIndent()
        val httpClient = metadataHttpClient(
            mapOf(
                "/.well-known/jwt-vc-issuer/api/v1/openid4vci" to metadataJson,
                "/public_keys.jwks" to com.nimbusds.jose.jwk.JWKSet(signingKey.toPublicJWK()).toString(false),
            ),
        )
        val verifier = PolicyAwareSdJwtVcJwtSignatureVerifier(
            x509CertificateTrust = X509CertificateTrust.None as X509CertificateTrust<List<java.security.cert.X509Certificate>>,
            issuerMetadataJwkSetResolver = IssuerMetadataJwkSetResolver(
                httpClient,
                IssuerMetadataTrustPolicy(setOf(Regex("https://issuer\\.example/.*"))),
            ),
        )

        val signedJwt = buildSdJwtVc(issuer, signingKey)

        assertNotNull(verifier.checkSignature(signedJwt))
    }

    @Test
    fun `rejects issuer metadata verification for issuer outside allowlist`() = runTest {
        val issuer = "https://issuer.example/api/v1/openid4vci"
        val signingKey = ECKeyGenerator(Curve.P_256)
            .keyUse(KeyUse.SIGNATURE)
            .keyID("issuer-key-1")
            .generate()
        val verifier = PolicyAwareSdJwtVcJwtSignatureVerifier(
            x509CertificateTrust = X509CertificateTrust.None as X509CertificateTrust<List<java.security.cert.X509Certificate>>,
            issuerMetadataJwkSetResolver = IssuerMetadataJwkSetResolver(
                metadataHttpClient(emptyMap()),
                IssuerMetadataTrustPolicy.Disabled,
            ),
        )

        val error = runCatching { verifier.checkSignature(buildSdJwtVc(issuer, signingKey)) }.exceptionOrNull()

        assertTrue(error is SdJwtVerificationException)
    }

    @Test
    fun `ignored trust mode keeps x5c-backed credentials valid`() = runTest {
        val (_, issuerCertHolder) = CertOps.genTrustAnchor(
            sigAlg = "SHA256withECDSA",
            name = X500Name("CN=Issuer"),
        )
        val trust = x509CertificateTrust(ProvideTrustSource.forAll(X5CShouldBe.Ignored))

        val isTrusted = trust.isTrusted(
            listOf(issuerCertHolder.toCertificate()),
            buildJsonObject { put("vct", "urn:example:vct") },
        )

        assertTrue(isTrusted)
    }
}

private fun buildSdJwtVc(
    issuer: String,
    signingKey: com.nimbusds.jose.jwk.ECKey,
): String {
    val jwt = com.nimbusds.jwt.SignedJWT(
        JWSHeader.Builder(JWSAlgorithm.ES256)
            .keyID(signingKey.keyID)
            .type(JOSEObjectType("dc+sd-jwt"))
            .build(),
        JWTClaimsSet.Builder()
            .issuer(issuer)
            .claim("vct", "urn:example:vct")
            .build(),
    )
    jwt.sign(ECDSASigner(signingKey))
    return jwt.serialize()
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
