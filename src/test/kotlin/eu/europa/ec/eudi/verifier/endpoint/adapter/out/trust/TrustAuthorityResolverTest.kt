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
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class TrustAuthorityResolverTest {

    @Test
    fun `query without trusted authorities uses default trust resolution`() = runTest {
        val resolver = TrustAuthorityResolverLive(FetchLOTLCertificates { Either.Right(emptyList()) })
        val policy = PresentationTrustPolicy.from(VerifierApiClient.loadInitTransactionTO("fixtures/eudi/00-dcql.json").dcqlQuery!!)

        assertNull(resolver.resolve(QueryId("wa_driver_license"), policy).getOrNull())
    }

    @Test
    fun `etsi trusted authority resolves trusted certificates`() = runTest {
        var capturedConfig: TrustedListConfig? = null
        val resolver = TrustAuthorityResolverLive(
            FetchLOTLCertificates { config ->
                capturedConfig = config
                Either.Right(TestContext.signingCertificateChain)
            },
        )
        val policy = PresentationTrustPolicy.from(dcqlWithTrustedAuthorities())

        val trust = assertIs<X5CShouldBe.Trusted>(
            resolver.resolve(QueryId("wa_driver_license"), policy).getOrNull(),
        )

        assertEquals(TestContext.signingCertificateChain.size, trust.rootCACertificates.size)
        assertEquals(ProviderKind.eudiAttestationProviderKinds, assertNotNull(capturedConfig).serviceTypeFilters)
    }

    @Test
    fun `etsi trusted authority on pid query resolves pid-compatible provider certificates`() = runTest {
        var capturedConfig: TrustedListConfig? = null
        val resolver = TrustAuthorityResolverLive(
            FetchLOTLCertificates { config ->
                capturedConfig = config
                Either.Right(TestContext.signingCertificateChain)
            },
        )
        val policy = PresentationTrustPolicy.from(pidDcqlWithTrustedAuthorities())

        val trust = assertIs<X5CShouldBe.Trusted>(
            resolver.resolve(QueryId("pid"), policy).getOrNull(),
        )

        assertEquals(TestContext.signingCertificateChain.size, trust.rootCACertificates.size)
        assertEquals(ProviderKind.eudiPidProviderKinds, assertNotNull(capturedConfig).serviceTypeFilters)
    }

    @Test
    fun `etsi trusted authority fetch failures are returned`() = runTest {
        val resolver = TrustAuthorityResolverLive(
            FetchLOTLCertificates { Either.Left(IllegalStateException("network down")) },
        )
        val policy = PresentationTrustPolicy.from(dcqlWithTrustedAuthorities())

        assertIs<TrustAuthorityResolutionError.TrustedListFetchFailed>(
            resolver.resolve(QueryId("wa_driver_license"), policy).leftOrNull(),
        )
    }

    @Test
    fun `etsi trusted authority rejects non https locations before fetching`() = runTest {
        val resolver = TrustAuthorityResolverLive(
            FetchLOTLCertificates { error("should not fetch untrusted locations") },
        )
        val policy = PresentationTrustPolicy.from(
            dcqlWithTrustedAuthorities("http://trust.example/lote.jwt"),
        )

        assertIs<TrustAuthorityResolutionError.TrustedListFetchFailed>(
            resolver.resolve(QueryId("wa_driver_license"), policy).leftOrNull(),
        )
    }

    @Test
    fun `etsi trusted authority rejects local locations before fetching`() = runTest {
        val resolver = TrustAuthorityResolverLive(
            FetchLOTLCertificates { error("should not fetch local locations") },
        )
        val policy = PresentationTrustPolicy.from(
            dcqlWithTrustedAuthorities("https://localhost/lote.jwt"),
        )

        assertIs<TrustAuthorityResolutionError.TrustedListFetchFailed>(
            resolver.resolve(QueryId("wa_driver_license"), policy).leftOrNull(),
        )
    }

    @Test
    fun `aki trusted authority is unsupported until chain validation is implemented`() = runTest {
        val resolver = TrustAuthorityResolverLive(
            FetchLOTLCertificates { Either.Right(TestContext.signingCertificateChain) },
        )
        val policy = PresentationTrustPolicy.from(dcqlWithAuthorityKeyIdentifier())

        val error = assertIs<TrustAuthorityResolutionError.UnsupportedType>(
            resolver.resolve(QueryId("wa_driver_license"), policy).leftOrNull(),
        )

        assertEquals(TrustedAuthorityType.AuthorityKeyIdentifier, error.type)
    }

    @Test
    fun `openid federation trusted authority is unsupported until federation chain validation is implemented`() = runTest {
        val resolver = TrustAuthorityResolverLive(
            FetchLOTLCertificates { Either.Right(TestContext.signingCertificateChain) },
        )
        val policy = PresentationTrustPolicy.from(dcqlWithOpenIdFederationAuthority())

        val error = assertIs<TrustAuthorityResolutionError.UnsupportedType>(
            resolver.resolve(QueryId("wa_driver_license"), policy).leftOrNull(),
        )

        assertEquals(TrustedAuthorityType.OpenIdFederation, error.type)
    }

    private fun dcqlWithTrustedAuthorities(location: String = "https://8.8.8.8/lote.jwt"): DCQL {
        val dcql = VerifierApiClient.loadInitTransactionTO("fixtures/eudi/00-dcql.json").dcqlQuery!!
        return dcql.copy(
            credentials = Credentials(
                dcql.credentials.value.mapIndexed { index, credential ->
                    if (index == 0) {
                        credential.copy(
                            trustedAuthorities = listOf(
                                TrustedAuthority(
                                    TrustedAuthorityType.TrustedList,
                                    listOf(location),
                                ),
                            ),
                        )
                    } else {
                        credential
                    }
                },
            ),
        )
    }

    private fun dcqlWithAuthorityKeyIdentifier(): DCQL {
        val dcql = VerifierApiClient.loadInitTransactionTO("fixtures/eudi/00-dcql.json").dcqlQuery!!
        return dcql.copy(
            credentials = Credentials(
                dcql.credentials.value.mapIndexed { index, credential ->
                    if (index == 0) {
                        credential.copy(
                            trustedAuthorities = listOf(
                                TrustedAuthority.authorityKeyIdentifiers(listOf("s9tIpPmhxdiuNkHMEWNpYim8S8Y")),
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

    private fun pidDcqlWithTrustedAuthorities(): DCQL =
        DCQL(
            credentials = Credentials(
                listOf(
                    CredentialQuery.mdoc(
                        id = QueryId("pid"),
                        msoMdocMeta = DCQLMetaMsoMdocExtensions(MsoMdocDocType("eu.europa.ec.eudi.pid.1")),
                        trustedAuthorities = listOf(
                            TrustedAuthority.trustedLists(listOf(URL("https://8.8.8.8/lote.jwt"))),
                        ),
                    ),
                ),
            ),
        )
}
