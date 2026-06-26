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
import arrow.core.getOrElse
import arrow.core.raise.*
import arrow.core.toNonEmptyListOrNull
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.SkipRevocation
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.X5CShouldBe
import eu.europa.ec.eudi.verifier.endpoint.domain.PresentationTrustPolicy
import eu.europa.ec.eudi.verifier.endpoint.domain.QueryId
import eu.europa.ec.eudi.verifier.endpoint.domain.TrustedAuthorityType
import eu.europa.ec.eudi.verifier.endpoint.domain.TrustedListConfig
import eu.europa.ec.eudi.verifier.endpoint.port.out.lotl.FetchLOTLCertificates
import java.net.InetAddress
import java.net.URI
import java.net.URL

sealed interface TrustAuthorityResolutionError {
    data class UnsupportedType(val type: TrustedAuthorityType) : TrustAuthorityResolutionError
    data object NoTrustedCertificates : TrustAuthorityResolutionError
    data class TrustedListFetchFailed(val message: String?) : TrustAuthorityResolutionError
}

fun interface TrustAuthorityResolver {
    suspend fun resolve(
        queryId: QueryId,
        policy: PresentationTrustPolicy,
    ): Either<TrustAuthorityResolutionError, X5CShouldBe?>
}

class TrustAuthorityResolverLive(
    private val fetchLOTLCertificates: FetchLOTLCertificates,
) : TrustAuthorityResolver {

    override suspend fun resolve(
        queryId: QueryId,
        policy: PresentationTrustPolicy,
    ): Either<TrustAuthorityResolutionError, X5CShouldBe?> = either {
        val authorities = policy.authoritiesFor(queryId) ?: return@either null
        val trustedListAuthorities = authorities.filter { it.type == TrustedAuthorityType.TrustedList }
        val unsupported = authorities.firstOrNull {
            it.type != TrustedAuthorityType.TrustedList
        }
        if (unsupported != null) {
            raise(TrustAuthorityResolutionError.UnsupportedType(unsupported.type))
        }

        val trustedListCertificates =
            trustedListAuthorities.flatMap { authority ->
                authority.values.flatMap { value ->
                    val location = trustedListLocation(value)
                        .getOrElse { error ->
                            raise(error)
                        }
                    fetchLOTLCertificates(
                        TrustedListConfig(
                            location = location,
                            serviceTypeFilter = null,
                            keystoreConfig = null,
                            serviceTypeFilters = policy.serviceTypeFiltersFor(queryId),
                        ),
                    ).mapLeft { error ->
                        TrustAuthorityResolutionError.TrustedListFetchFailed(
                            error.message,
                        )
                    }.bind()
                }
            }

        val policies = buildList {
            if (trustedListAuthorities.isNotEmpty()) {
                val roots = trustedListCertificates.toNonEmptyListOrNull()
                ensure(roots != null) { TrustAuthorityResolutionError.NoTrustedCertificates }
                add(X5CShouldBe.Trusted(roots, SkipRevocation))
            }
        }
        policies.toTrustPolicy()
    }
}

private fun trustedListLocation(value: String): Either<TrustAuthorityResolutionError.TrustedListFetchFailed, URL> =
    Either.catch {
        val uri = URI(value)
        require(uri.scheme == "https") { "trusted list location must use https" }
        require(uri.userInfo == null) { "trusted list location must not include userinfo" }
        require(!uri.host.isNullOrBlank()) { "trusted list location must include a host" }
        require(InetAddress.getAllByName(uri.host).none(InetAddress::isLocalAddress)) {
            "trusted list location must not resolve to a local address"
        }
        uri.toURL()
    }.mapLeft { error ->
        TrustAuthorityResolutionError.TrustedListFetchFailed(error.message)
    }

private fun List<X5CShouldBe>.toTrustPolicy(): X5CShouldBe? =
    when (val policies = toNonEmptyListOrNull()) {
        null -> null
        else -> policies.toTrustPolicy()
    }

private fun NonEmptyList<X5CShouldBe>.toTrustPolicy(): X5CShouldBe =
    if (size == 1) head else X5CShouldBe.OneOf(this)

private fun InetAddress.isLocalAddress(): Boolean =
    isAnyLocalAddress || isLoopbackAddress || isLinkLocalAddress || isSiteLocalAddress || isMulticastAddress
