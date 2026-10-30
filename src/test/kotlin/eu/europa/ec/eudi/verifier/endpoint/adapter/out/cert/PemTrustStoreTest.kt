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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert

import arrow.core.nonEmptyListOf
import kotlinx.coroutines.test.runTest
import java.security.cert.X509Certificate
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PemTrustStoreTest {

    private fun X509Certificate.toPem(): String =
        "-----BEGIN CERTIFICATE-----\n" +
            Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(encoded) +
            "\n-----END CERTIFICATE-----\n"

    @Test
    fun `PEM trust anchors validate a chain that ends in one of them`() = runTest {
        val (trusted, endEntity) = Sample.create()
        val store = pemTrustStore(trusted.trustCert.toPem() + trusted.caCert.toPem())

        assertEquals(2, store.size())
        val validated = X5CValidator(X5CShouldBe.fromKeystore(store)).ensureTrusted(nonEmptyListOf(endEntity, trusted.caCert))
        assertTrue(validated.isRight())
    }

    @Test
    fun `PEM trust anchors refuse a chain from another root`() = runTest {
        val (trusted, _) = Sample.create()
        val (otherCa, otherEndEntity) = Sample.create()
        val store = pemTrustStore(trusted.trustCert.toPem())

        val validated = X5CValidator(X5CShouldBe.fromKeystore(store)).ensureTrusted(nonEmptyListOf(otherEndEntity, otherCa.caCert))
        assertTrue(validated.isLeft())
    }

    @Test
    fun `text without certificates is rejected`() {
        assertFailsWith<IllegalArgumentException> { pemTrustStore("not a certificate") }
    }

    @Test
    fun `trust sources without an entry for a type give no trust`() = runTest {
        assertNull(TrustSources()("urn:vc:authbound:pid:1.0"))
    }

    @Test
    fun `a trust source that loaded no certificates gives no trust`() = runTest {
        val trustSources = TrustSources()
        trustSources.updateWithX5CShouldBe(Regex(".*"), emptyList())

        assertNull(trustSources("urn:vc:authbound:pid:1.0"))
    }
}
