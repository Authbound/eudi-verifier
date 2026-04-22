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
@file:Suppress("invisible_reference", "invisible_member")

package eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose

import arrow.core.toNonEmptyListOrNull
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.util.X509CertUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata
import eu.europa.ec.eudi.verifier.endpoint.TestContext
import eu.europa.ec.eudi.verifier.endpoint.adapter.input.web.TestUtils
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.decodeAs
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.toJsonObject
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.utils.getOrThrow
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.x509.dropRootCAIfPresent
import eu.europa.ec.eudi.verifier.endpoint.domain.SigningConfig
import eu.europa.ec.eudi.verifier.endpoint.domain.VerifierId
import eu.europa.ec.eudi.verifier.endpoint.domain.DCQL
import eu.europa.ec.eudi.verifier.endpoint.domain.Clock
import eu.europa.ec.eudi.verifier.endpoint.domain.EmbedOption
import eu.europa.ec.eudi.verifier.endpoint.domain.GetWalletResponseMethod
import eu.europa.ec.eudi.verifier.endpoint.domain.HashAlgorithm
import eu.europa.ec.eudi.verifier.endpoint.domain.Nonce
import eu.europa.ec.eudi.verifier.endpoint.domain.OpenId4VPSpec
import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation
import eu.europa.ec.eudi.verifier.endpoint.domain.Profile
import eu.europa.ec.eudi.verifier.endpoint.domain.RequestId
import eu.europa.ec.eudi.verifier.endpoint.domain.RequestUriMethod
import eu.europa.ec.eudi.verifier.endpoint.domain.ResponseMode
import eu.europa.ec.eudi.verifier.endpoint.domain.ResponseModeOption
import eu.europa.ec.eudi.verifier.endpoint.domain.TransactionId
import eu.europa.ec.eudi.verifier.endpoint.domain.UnresolvedAuthorizationRequestUri
import eu.europa.ec.eudi.verifier.endpoint.domain.VerifierConfig
import eu.europa.ec.eudi.verifier.endpoint.port.input.InitTransactionTO
import eu.europa.ec.eudi.verifier.endpoint.domain.toJavaDate
import kotlinx.datetime.TimeZone
import kotlinx.serialization.json.Json
import net.minidev.json.JSONObject
import java.net.URL
import java.util.*
import kotlin.test.*
import kotlin.time.Duration.Companion.minutes

class CreateJarNimbusTest {

    private val createJar = TestContext.createJar
    private val verifier = TestContext.signedRequestObjectVerifier
    private val clientMetaData = TestContext.clientMetaData
    private val verifierId = TestContext.verifierId

    @Test
    fun `given a request object, it should be signed and decoded`() {
        val query = Json.decodeFromString<InitTransactionTO>(TestUtils.loadResource("fixtures/eudi/02-dcql.json")).dcqlQuery
        val requestObject = RequestObject(
            verifierId = verifierId,
            responseType = listOf("vp_token"),
            dcqlQuery = query,
            scope = listOf("openid"),
            nonce = UUID.randomUUID().toString(),
            responseMode = "direct_post.jwt",
            responseUri = URL("https://foo"),
            state = TestContext.testRequestId.value,
            aud = emptyList(),
            issuedAt = TestContext.testClock.now(),
            expiresAt = TestContext.testClock.now() + 15.minutes,
        )

        // responseMode is direct_post.jwt, so we need to generate an ephemeral key
        val ecKey = ECKeyGenerator(Curve.P_256)
            .keyUse(KeyUse.ENCRYPTION)
            .algorithm(JWEAlgorithm.ECDH_ES)
            .keyID(UUID.randomUUID().toString())
            .generate()

        val jwt = createJar.sign(clientMetaData, ResponseMode.DirectPostJwt(ecKey), requestObject, null)
            .getOrThrow()
            .serialize()
            .also { println(it) }
        val signedJwt = decode(jwt).getOrThrow().also { println(it) }
        assertX5cHeaderClaimDoesNotContainPEM(signedJwt.header)
        val claimSet = signedJwt.jwtClaimsSet
        assertEqualsRequestObjectJWTClaimSet(requestObject, claimSet)

        assertTrue { claimSet.claims.containsKey("client_metadata") }
        val rawClientMetadata = claimSet.getJSONObjectClaim("client_metadata")
        assertEquals(rawClientMetadata[OpenId4VPSpec.VP_FORMATS], rawClientMetadata[OpenId4VPSpec.VP_FORMATS_SUPPORTED])
        val clientMetadata = OIDCClientMetadata.parse(JSONObject(rawClientMetadata))
        assertNull(clientMetadata.jwkSetURI)
        assertEquals(JWKSet(ecKey).toPublicJWKSet(), clientMetadata.jwkSet)
    }

    @Test
    fun `given explicit certificate chain, x509_san_dns signing should not depend on x5c embedded in jwk`() {
        val strippedKey = TestContext.signingPrivateJwkWithoutCertificateChain
        assertNull(strippedKey.parsedX509CertChain)

        val verifierId = VerifierId.X509SanDns(
            "verifier",
            SigningConfig(
                key = strippedKey,
                algorithm = JWSAlgorithm.ES512,
                certificateChain = TestContext.signingCertificateChain,
            ),
        )
        val requestObject = requestObject(verifierId)
        val responseEncryptionKey = ECKeyGenerator(Curve.P_256)
            .keyUse(KeyUse.ENCRYPTION)
            .algorithm(JWEAlgorithm.ECDH_ES)
            .keyID(UUID.randomUUID().toString())
            .generate()

        val signedJwt = createJar.sign(clientMetaData, ResponseMode.DirectPostJwt(responseEncryptionKey), requestObject, null)
            .getOrThrow()

        assertNull(signedJwt.header.keyID)
        val chain = assertNotNull(signedJwt.header.x509CertChain)
        val expectedChain = TestContext.signingCertificateChain.dropRootCAIfPresent()
        assertEquals(expectedChain.size, chain.size)
        expectedChain.zip(chain).forEach { (expected, actual) ->
            assertContentEquals(expected.encoded, actual.decode())
        }
        assertX5cHeaderClaimDoesNotContainPEM(signedJwt.header)
        assertTrue(signedJwt.verify(verifier))
    }

    @Test
    fun `pre-registered signing should work without a certificate chain`() {
        val strippedKey = TestContext.signingPrivateJwkWithoutCertificateChain
        assertNull(strippedKey.parsedX509CertChain)

        val verifierId = VerifierId.PreRegistered(
            "verifier",
            SigningConfig(
                key = strippedKey,
                algorithm = JWSAlgorithm.ES512,
            ),
        )
        val requestObject = requestObject(verifierId)
        val responseEncryptionKey = ECKeyGenerator(Curve.P_256)
            .keyUse(KeyUse.ENCRYPTION)
            .algorithm(JWEAlgorithm.ECDH_ES)
            .keyID(UUID.randomUUID().toString())
            .generate()

        val signedJwt = createJar.sign(clientMetaData, ResponseMode.DirectPostJwt(responseEncryptionKey), requestObject, null)
            .getOrThrow()

        assertEquals(strippedKey.keyID, signedJwt.header.keyID)
        assertNull(signedJwt.header.x509CertChain)
        assertTrue(signedJwt.verify(verifier))
    }

    @Test
    fun `request object expiration is capped to original presentation deadline`() {
        val requested = requestedPresentation()
        val signingClock = Clock.fixed(requested.initiatedAt + 10.minutes, TimeZone.UTC)

        val requestObject = requestObjectFromDomain(verifierConfig(), signingClock, requested)

        assertEquals(signingClock.now(), requestObject.issuedAt)
        assertEquals(requested.initiatedAt + 15.minutes, requestObject.expiresAt)
    }

    private fun requestObject(verifierId: VerifierId): RequestObject {
        val query = Json.decodeFromString<InitTransactionTO>(TestUtils.loadResource("fixtures/eudi/02-dcql.json")).dcqlQuery
        return RequestObject(
            verifierId = verifierId,
            responseType = listOf("vp_token"),
            dcqlQuery = query,
            scope = listOf("openid"),
            nonce = UUID.randomUUID().toString(),
            responseMode = "direct_post.jwt",
            responseUri = URL("https://foo"),
            state = TestContext.testRequestId.value,
            aud = emptyList(),
            issuedAt = TestContext.testClock.now(),
            expiresAt = TestContext.testClock.now() + 15.minutes,
        )
    }

    private fun requestedPresentation(): Presentation.Requested {
        val query = Json.decodeFromString<InitTransactionTO>(TestUtils.loadResource("fixtures/eudi/02-dcql.json")).dcqlQuery!!
        return Presentation.Requested(
            id = TransactionId("tx-${UUID.randomUUID()}"),
            initiatedAt = TestContext.testClock.now(),
            query = query,
            transactionData = null,
            requestId = RequestId("req-${UUID.randomUUID()}"),
            requestUriMethod = RequestUriMethod.Get,
            nonce = Nonce("nonce-${UUID.randomUUID()}"),
            responseMode = ResponseMode.DirectPost,
            getWalletResponseMethod = GetWalletResponseMethod.Poll,
            issuerChain = null,
            profile = Profile.OpenId4VP,
        )
    }

    private fun verifierConfig(): VerifierConfig =
        VerifierConfig(
            verifierId = verifierId,
            requestJarOption = EmbedOption.ByReference { _ -> URL("https://verifier.example/request.jwt") },
            responseUriBuilder = { _ -> URL("https://verifier.example/response") },
            responseModeOption = ResponseModeOption.DirectPost,
            maxAge = 15.minutes,
            clientMetaData = clientMetaData,
            transactionDataHashAlgorithm = HashAlgorithm.SHA_256,
            requestUriMethod = RequestUriMethod.Get,
            authorizationRequestUri = UnresolvedAuthorizationRequestUri.fromUri("haip-vp://").getOrThrow(),
            trustSourcesConfig = emptyMap(),
            issuerMetadataAllowedIssuerPatterns = emptySet(),
        )

    private fun decode(jwt: String): Result<SignedJWT> {
        return runCatching {
            val signedJWT = SignedJWT.parse(jwt)
            signedJWT.verify(verifier)
            signedJWT
        }
    }

    private fun assertEqualsRequestObjectJWTClaimSet(r: RequestObject, c: JWTClaimsSet) {
        assertEquals(r.verifierId.clientId, c.getStringClaim("client_id"))
        assertEquals(r.responseType.joinToString(separator = " "), c.getStringClaim("response_type"))
        assertEquals(
            r.dcqlQuery,
            c.getJSONObjectClaim(OpenId4VPSpec.DCQL_QUERY).toJsonObject().decodeAs<DCQL>().getOrThrow(),
        )
        assertEquals(r.scope.joinToString(separator = " "), c.getStringClaim("scope"))
        assertEquals(r.nonce, c.getStringClaim("nonce"))
        assertEquals(r.responseMode, c.getStringClaim("response_mode"))
        assertEquals(r.responseUri?.toExternalForm(), c.getStringClaim(OpenId4VPSpec.RESPONSE_URI))
        assertEquals(r.state, c.getStringClaim("state"))
        assertEquals(r.issuedAt.toJavaDate(), c.issueTime)
        assertEquals(r.expiresAt.toJavaDate(), c.expirationTime)
    }

    private fun assertX5cHeaderClaimDoesNotContainPEM(header: JWSHeader) {
        val chain = assertNotNull(header.x509CertChain?.toNonEmptyListOrNull())
        chain.forEach {
            // Ensure it is not a base64 encoded PEM
            assertNull(X509CertUtils.parse(it.decodeToString()))

            // Ensure it is a base64 encoded DER
            assertNotNull(X509CertUtils.parse(it.decode()))
        }
    }
}
