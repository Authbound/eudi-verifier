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

data class PresentationTrustPolicy(
    private val authoritiesByQueryId: Map<QueryId, List<TrustedAuthority>>,
) {
    fun authoritiesFor(queryId: QueryId): List<TrustedAuthority>? =
        authoritiesByQueryId[queryId]

    companion object {
        fun from(dcql: DCQL): PresentationTrustPolicy =
            PresentationTrustPolicy(
                dcql.credentials.value
                    .mapNotNull { credential ->
                        credential.trustedAuthorities?.let { credential.id to it }
                    }
                    .toMap(),
            )
    }
}
