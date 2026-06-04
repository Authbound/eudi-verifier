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
package eu.europa.ec.eudi.verifier.endpoint.domain

class PresentationTrustPolicy private constructor(
    private val credentialTrustByQueryId: Map<QueryId, CredentialTrust>,
) {
    fun authoritiesFor(queryId: QueryId): List<TrustedAuthority>? =
        credentialTrustByQueryId[queryId]?.trustedAuthorities

    fun serviceTypeFiltersFor(queryId: QueryId): Set<ProviderKind> =
        credentialTrustByQueryId[queryId]?.serviceTypeFilters ?: ProviderKind.eudiCredentialProviderKinds

    companion object {
        fun from(dcql: DCQL): PresentationTrustPolicy =
            PresentationTrustPolicy(
                dcql.credentials.value
                    .mapNotNull { credential ->
                        credential.trustedAuthorities?.let {
                            credential.id to CredentialTrust(
                                trustedAuthorities = it,
                                serviceTypeFilters = credential.serviceTypeFilters(),
                            )
                        }
                    }
                    .toMap(),
            )
    }
}

private data class CredentialTrust(
    val trustedAuthorities: List<TrustedAuthority>,
    val serviceTypeFilters: Set<ProviderKind>,
)

private fun CredentialQuery.serviceTypeFilters(): Set<ProviderKind> =
    when (format) {
        Format.MsoMdoc ->
            if (metaMsoMdoc?.doctypeValue?.value?.isPidTypeIdentifier() == true) {
                ProviderKind.eudiPidProviderKinds
            } else {
                ProviderKind.eudiAttestationProviderKinds
            }

        Format.SdJwtVc -> {
            val vctValues = metaSdJwtVc?.vctValues.orEmpty()
            buildSet {
                if (vctValues.any { it.isPidTypeIdentifier() }) {
                    addAll(ProviderKind.eudiPidProviderKinds)
                }
                if (vctValues.any { !it.isPidTypeIdentifier() }) {
                    addAll(ProviderKind.eudiAttestationProviderKinds)
                }
            }.ifEmpty { ProviderKind.eudiCredentialProviderKinds }
        }

        else -> ProviderKind.eudiCredentialProviderKinds
    }

private fun String.isPidTypeIdentifier(): Boolean {
    val normalized = lowercase()
    return normalized == "pid" ||
        normalized.contains(":pid:") ||
        normalized.endsWith(":pid") ||
        normalized.contains(".pid.") ||
        normalized.endsWith(".pid")
}
