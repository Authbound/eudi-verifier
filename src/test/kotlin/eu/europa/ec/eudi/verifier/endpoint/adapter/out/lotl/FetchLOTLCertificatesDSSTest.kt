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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.lotl

import eu.europa.ec.eudi.verifier.endpoint.adapter.out.utils.getOrThrow
import eu.europa.ec.eudi.verifier.endpoint.domain.ProviderKind
import eu.europa.ec.eudi.verifier.endpoint.domain.TrustedListConfig
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.net.URI
import java.net.UnknownHostException
import java.security.KeyStore

class FetchLOTLCertificatesDSSTest {

    @Test
    fun `trusted list loader refuses local fetch targets`() {
        val loader = SafeTrustedListDataLoader()

        assertThrows<UnknownHostException> {
            loader.get("https://localhost/lotl.xml")
        }
    }

    @Test
    fun `trusted list loader disables redirects`() {
        assertFalse(SafeTrustedListDataLoader().isRedirectsEnabled)
    }

    @Test
    fun `trusted list dns resolver refuses local addresses`() {
        assertThrows<UnknownHostException> {
            PublicOnlyDnsResolver.resolve("localhost")
        }
    }

    @Test
    fun `trusted list dns resolver refuses private address literals`() {
        assertThrows<UnknownHostException> {
            PublicOnlyDnsResolver.resolve("100.64.0.1")
        }
    }

    @Test
    fun `trusted list service predicate accepts only configured eudi credential provider types`() {
        val config = TrustedListConfig(
            URI("https://trust.example/lote.jwt").toURL(),
            serviceTypeFilter = null,
            keystoreConfig = null,
            serviceTypeFilters = ProviderKind.eudiAttestationProviderKinds,
        )

        assertTrue(config.matchesServiceType(ProviderKind.EAAProvider.value))
        assertTrue(config.matchesServiceType("http://uri.etsi.org/19602/SvcType/EAA/Issuance"))
        assertTrue(config.matchesServiceType(ProviderKind.QEEAProvider.value))
        assertTrue(config.matchesServiceType("http://uri.etsi.org/19602/SvcType/QEAA/Issuance"))
        assertTrue(config.matchesServiceType("http://uri.etsi.org/19602/SvcType/EAA/Q/Issuance"))
        assertTrue(config.matchesServiceType(ProviderKind.PubEAAProvider.value))
        assertTrue(config.matchesServiceType("http://uri.etsi.org/19602/SvcType/PubEAA/Issuance"))
        assertFalse(config.matchesServiceType(ProviderKind.PIDProvider.value))
        assertFalse(config.matchesServiceType("http://uri.etsi.org/19602/SvcType/PID/Issuance"))
        assertFalse(config.matchesServiceType("http://uri.etsi.org/19602/SvcType/EAA/Revocation"))
        assertFalse(config.matchesServiceType("http://uri.etsi.org/TrstSvc/Svctype/CA/QC"))
    }

    @Test
    fun `trusted list service predicate accepts supported pid provider profile types`() {
        val config = TrustedListConfig(
            URI("https://trust.example/lote.jwt").toURL(),
            serviceTypeFilter = null,
            keystoreConfig = null,
            serviceTypeFilters = setOf(ProviderKind.PIDProvider),
        )

        assertTrue(config.matchesServiceType("https://ewc-consortium.github.io/ewc-trust-list/TrstSvc/Svctype/PID"))
        assertTrue(config.matchesServiceType("http://uri.etsi.org/Svc/Svctype/Provider/PID"))
        assertTrue(config.matchesServiceType("http://uri.etsi.org/19602/SvcType/PID/Issuance"))
        assertTrue(config.matchesServiceType("http://uri.etsi.org/19602/SvcType/EAA/Issuance"))
        assertFalse(config.matchesServiceType(ProviderKind.EAAProvider.value))
        assertFalse(config.matchesServiceType("http://uri.etsi.org/TrstSvc/Svctype/CA/QC"))
    }

    // @Test
    fun `get certs`() = runTest {
        val fetchLOTLCertificatesDSS = FetchLOTLCertificatesDSS()

        val certificates = fetchLOTLCertificatesDSS(
            TrustedListConfig(
                URI("https://ec.europa.eu/tools/lotl/eu-lotl.xml").toURL(),
                null,
                "0 *",
                keystoreConfig = null,
            ),
        ).getOrThrow()
        assertTrue(certificates.isNotEmpty())

        val keyStore = KeyStore.getInstance("JKS")
        keyStore.load(null, null)

        certificates.forEachIndexed { index, cert ->
            keyStore.setCertificateEntry("cert_$index", cert)
        }

        assertEquals(certificates.size, keyStore.aliases().toList().size)
    }
}
