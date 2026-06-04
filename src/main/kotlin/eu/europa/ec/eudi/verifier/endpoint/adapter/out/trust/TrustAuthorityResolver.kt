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
import arrow.core.NonEmptyList
import arrow.core.toNonEmptyListOrNull
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.FetchOpenIdFederationEntityConfiguration
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.SkipRevocation
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.X5CShouldBe
import eu.europa.ec.eudi.verifier.endpoint.domain.PresentationTrustPolicy
import eu.europa.ec.eudi.verifier.endpoint.domain.ProviderKind
import eu.europa.ec.eudi.verifier.endpoint.domain.QueryId
import eu.europa.ec.eudi.verifier.endpoint.domain.TrustedAuthorityType
import eu.europa.ec.eudi.verifier.endpoint.domain.TrustedListConfig
import eu.europa.ec.eudi.verifier.endpoint.port.out.lotl.FetchLOTLCertificates
import java.net.URI

sealed interface TrustAuthorityResolutionError {
    data class UnsupportedType(val type: TrustedAuthorityType) : TrustAuthorityResolutionError
    data object NoTrustedCertificates : TrustAuthorityResolutionError
}

fun interface TrustAuthorityResolver {
    suspend fun resolve(
        queryId: QueryId,
        policy: PresentationTrustPolicy,
    ): Either<TrustAuthorityResolutionError, X5CShouldBe?>
}

class TrustAuthorityResolverLive(
    private val fetchLOTLCertificates: FetchLOTLCertificates,
    private val fetchOpenIdFederationEntityConfiguration: FetchOpenIdFederationEntityConfiguration =
        FetchOpenIdFederationEntityConfigurationHttp(),
) : TrustAuthorityResolver {

    override suspend fun resolve(
        queryId: QueryId,
        policy: PresentationTrustPolicy,
    ): Either<TrustAuthorityResolutionError, X5CShouldBe?> =
        Either.catch {
            val authorities = policy.authoritiesFor(queryId) ?: return@catch null
            val authorityKeyIdentifierAuthorities = authorities.filter {
                it.type == TrustedAuthorityType.AuthorityKeyIdentifier
            }
            val trustedListAuthorities = authorities.filter { it.type == TrustedAuthorityType.TrustedList }
            val openIdFederationAuthorities = authorities.filter { it.type == TrustedAuthorityType.OpenIdFederation }
            val unsupported = authorities.firstOrNull {
                it.type != TrustedAuthorityType.AuthorityKeyIdentifier &&
                    it.type != TrustedAuthorityType.TrustedList &&
                    it.type != TrustedAuthorityType.OpenIdFederation
            }
            if (unsupported != null) {
                throw UnsupportedTrustedAuthorityType(unsupported.type)
            }

            val policies = buildList {
                authorityKeyIdentifierAuthorities
                    .flatMap { it.values }
                    .toNonEmptyListOrNull()
                    ?.let { add(X5CShouldBe.AuthorityKeyIdentifier(it)) }

                openIdFederationAuthorities
                    .flatMap { it.values }
                    .toNonEmptyListOrNull()
                    ?.let {
                        add(
                            X5CShouldBe.OpenIdFederation(
                                trustAnchors = it,
                                fetchEntityConfiguration = fetchOpenIdFederationEntityConfiguration,
                            ),
                        )
                    }

                if (trustedListAuthorities.isNotEmpty()) {
                    val certificates = trustedListAuthorities.flatMap { authority ->
                        authority.values.flatMap { value ->
                            fetchLOTLCertificates(
                                TrustedListConfig(
                                    location = URI(value).toURL(),
                                    serviceTypeFilter = ProviderKind.PIDProvider,
                                    keystoreConfig = null,
                                ),
                            ).getOrNull().orEmpty()
                        }
                    }
                    val roots = certificates.toNonEmptyListOrNull() ?: throw NoTrustedCertificates
                    add(X5CShouldBe.Trusted(roots, SkipRevocation))
                }
            }
            policies.toTrustPolicy()
        }.mapLeft { error ->
            when (error) {
                is UnsupportedTrustedAuthorityType -> TrustAuthorityResolutionError.UnsupportedType(error.type)
                NoTrustedCertificates -> TrustAuthorityResolutionError.NoTrustedCertificates
                else -> TrustAuthorityResolutionError.NoTrustedCertificates
            }
        }

    private data class UnsupportedTrustedAuthorityType(val type: TrustedAuthorityType) : RuntimeException()
    private data object NoTrustedCertificates : RuntimeException()
}

private fun List<X5CShouldBe>.toTrustPolicy(): X5CShouldBe? =
    when (val policies = toNonEmptyListOrNull()) {
        null -> null
        else -> policies.toTrustPolicy()
    }

private fun NonEmptyList<X5CShouldBe>.toTrustPolicy(): X5CShouldBe =
    if (size == 1) head else X5CShouldBe.OneOf(this)
