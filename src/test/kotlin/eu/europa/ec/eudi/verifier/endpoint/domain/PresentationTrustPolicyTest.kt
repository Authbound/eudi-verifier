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

import kotlin.test.Test
import kotlin.test.assertEquals

class PresentationTrustPolicyTest {

    @Test
    fun `sd-jwt vc pid vct uses pid provider service types`() {
        val credential = sdJwtVcCredential("pid", listOf("urn:eudi:pid:1"))

        assertEquals(ProviderKind.eudiPidProviderKinds, filtersFor(credential))
    }

    @Test
    fun `sd-jwt vc attestation vct uses attestation provider service types`() {
        val credential = sdJwtVcCredential("ehic", listOf("urn:eu.europa.ec.eudi:ehic:1"))

        assertEquals(ProviderKind.eudiAttestationProviderKinds, filtersFor(credential))
    }

    @Test
    fun `sd-jwt vc mixed vct values use pid and attestation provider service types`() {
        val credential = sdJwtVcCredential("mixed", listOf("urn:eudi:pid:1", "urn:eu.europa.ec.eudi:ehic:1"))

        assertEquals(ProviderKind.eudiCredentialProviderKinds, filtersFor(credential))
    }

    @Test
    fun `unknown credential type falls back to all eudi credential provider service types`() {
        val credential = CredentialQuery(
            id = QueryId("unknown"),
            format = Format.W3CJwtVcJson,
            meta = kotlinx.serialization.json.buildJsonObject {},
            trustedAuthorities = trustedAuthorities,
        )

        assertEquals(ProviderKind.eudiCredentialProviderKinds, filtersFor(credential))
    }

    private fun sdJwtVcCredential(id: String, vctValues: List<String>): CredentialQuery =
        CredentialQuery.sdJwtVc(
            id = QueryId(id),
            sdJwtVcMeta = DCQLMetaSdJwtVcExtensions(vctValues),
            trustedAuthorities = trustedAuthorities,
        )

    private fun filtersFor(credential: CredentialQuery): Set<ProviderKind> =
        PresentationTrustPolicy
            .from(DCQL(Credentials(credential)))
            .serviceTypeFiltersFor(credential.id)

    private companion object {
        val trustedAuthorities = listOf(
            TrustedAuthority(
                type = TrustedAuthorityType.TrustedList,
                values = listOf("https://ewc-consortium.github.io/ewc-trust-list/EWC-TL"),
            ),
        )
    }
}
