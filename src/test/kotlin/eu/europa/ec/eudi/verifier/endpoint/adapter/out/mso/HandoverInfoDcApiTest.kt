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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso

import arrow.core.toNonEmptyListOrNull
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import eu.europa.ec.eudi.verifier.endpoint.TestContext
import eu.europa.ec.eudi.verifier.endpoint.adapter.input.web.VerifierApiClient
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.utils.getOrThrow
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import org.junit.jupiter.api.Test
import java.net.URL
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.time.Duration.Companion.minutes

class HandoverInfoDcApiTest {

    @Test
    fun `dc api response mode uses dc api handover info`() {
        val expectedOrigin = URL("https://merchant.example")
        val requested = Presentation.Requested(
            id = TransactionId("tx-${UUID.randomUUID()}"),
            initiatedAt = TestContext.testClock.now(),
            query = VerifierApiClient.loadInitTransactionTO("fixtures/eudi/00-dcql.json").dcqlQuery!!,
            transactionData = null,
            requestId = RequestId("req-${UUID.randomUUID()}"),
            requestUriMethod = RequestUriMethod.Get,
            nonce = Nonce("nonce-${UUID.randomUUID()}"),
            responseMode = ResponseMode.DcApiJwt(
                ECKeyGenerator(Curve.P_256)
                    .keyUse(KeyUse.ENCRYPTION)
                    .algorithm(JWEAlgorithm.ECDH_ES)
                    .keyID(UUID.randomUUID().toString())
                    .generate(),
                listOf(expectedOrigin).toNonEmptyListOrNull()!!,
            ),
            getWalletResponseMethod = GetWalletResponseMethod.Poll,
            issuerChain = null,
            profile = Profile.OpenId4VP,
        )
        val retrieved = requested.retrieveRequestObject(TestContext.testClock).getOrThrow()

        val handover = assertIs<HandoverInfo.OpenID4VPDCAPIHandoverInfo>(
            HandoverInfo(retrieved, verifierConfig()),
        )

        assertEquals(expectedOrigin, handover.origin)
        assertEquals(requested.nonce, handover.nonce)
    }

    private fun verifierConfig(): VerifierConfig =
        VerifierConfig(
            verifierId = TestContext.verifierId,
            requestJarOption = EmbedOption.ByReference { _ -> URL("https://verifier.example/request.jwt") },
            responseUriBuilder = { _ -> URL("https://verifier.example/response") },
            responseModeOption = ResponseModeOption.DirectPostJwt,
            maxAge = 15.minutes,
            clientMetaData = TestContext.clientMetaData,
            transactionDataHashAlgorithm = HashAlgorithm.SHA_256,
            requestUriMethod = RequestUriMethod.Get,
            authorizationRequestUri = UnresolvedAuthorizationRequestUri.fromUri("haip-vp://").getOrThrow(),
            trustSourcesConfig = emptyMap(),
            issuerMetadataAllowedIssuerPatterns = emptySet(),
        )
}
