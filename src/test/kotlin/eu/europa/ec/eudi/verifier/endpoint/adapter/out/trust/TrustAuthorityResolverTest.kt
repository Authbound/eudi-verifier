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
import eu.europa.ec.eudi.verifier.endpoint.TestContext
import eu.europa.ec.eudi.verifier.endpoint.adapter.input.web.VerifierApiClient
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.X5CShouldBe
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.port.out.lotl.FetchLOTLCertificates
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Test
import java.net.URL
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull

class TrustAuthorityResolverTest {

    @Test
    fun `query without trusted authorities uses default trust resolution`() = runTest {
        val resolver = TrustAuthorityResolverLive(FetchLOTLCertificates { Either.Right(emptyList()) })
        val policy = PresentationTrustPolicy.from(VerifierApiClient.loadInitTransactionTO("fixtures/eudi/00-dcql.json").dcqlQuery!!)

        assertNull(resolver.resolve(QueryId("wa_driver_license"), policy).getOrNull())
    }

    @Test
    fun `etsi trusted authority resolves trusted certificates`() = runTest {
        val resolver = TrustAuthorityResolverLive(
            FetchLOTLCertificates { Either.Right(TestContext.signingCertificateChain) },
        )
        val policy = PresentationTrustPolicy.from(dcqlWithTrustedAuthorities())

        val trust = assertIs<X5CShouldBe.Trusted>(
            resolver.resolve(QueryId("wa_driver_license"), policy).getOrNull(),
        )

        assertEquals(TestContext.signingCertificateChain.size, trust.rootCACertificates.size)
    }

    @Test
    fun `openid federation trusted authority fails explicitly until federation resolver is wired`() = runTest {
        val resolver = TrustAuthorityResolverLive(FetchLOTLCertificates { Either.Right(TestContext.signingCertificateChain) })
        val policy = PresentationTrustPolicy.from(dcqlWithOpenIdFederationAuthority())

        val error = resolver.resolve(QueryId("wa_driver_license"), policy).leftOrNull()

        assertIs<TrustAuthorityResolutionError.UnsupportedType>(error)
    }

    private fun dcqlWithTrustedAuthorities(): DCQL {
        val dcql = VerifierApiClient.loadInitTransactionTO("fixtures/eudi/00-dcql.json").dcqlQuery!!
        return dcql.copy(
            credentials = Credentials(
                dcql.credentials.value.mapIndexed { index, credential ->
                    if (index == 0) {
                        credential.copy(
                            trustedAuthorities = listOf(
                                TrustedAuthority.trustedLists(listOf(URL("https://trust.example/lote.jwt"))),
                            ),
                        )
                    } else {
                        credential
                    }
                },
            ),
        )
    }

    private fun dcqlWithOpenIdFederationAuthority(): DCQL {
        val dcql = VerifierApiClient.loadInitTransactionTO("fixtures/eudi/00-dcql.json").dcqlQuery!!
        return dcql.copy(
            credentials = Credentials(
                dcql.credentials.value.mapIndexed { index, credential ->
                    if (index == 0) {
                        credential.copy(
                            trustedAuthorities = listOf(
                                TrustedAuthority.federatedEntities(listOf(URL("https://trust-anchor.example"))),
                            ),
                        )
                    } else {
                        credential
                    }
                },
            ),
        )
    }
}
