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

import arrow.core.Either
import arrow.core.Nel
import arrow.core.nonEmptyListOf
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier
import org.bouncycastle.asn1.x509.Extension
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.assertDoesNotThrow
import org.junit.jupiter.api.assertThrows
import java.security.cert.CertPathValidatorException
import java.security.cert.X509Certificate
import java.util.Base64
import kotlin.test.Test

data class TrustedCA(val trustCert: X509Certificate, val caCert: X509Certificate)

object Sample {
    private const val SIGN_ALG = "SHA256withECDSA"

    fun create(): Pair<TrustedCA, X509Certificate> = with(CertOps) {
        //
        // Trust Anchor
        //
        val name: X500Name =
            X500NameBuilder(BCStyle.INSTANCE).apply {
                addRDN(BCStyle.C, "Utopia")
                addRDN(BCStyle.O, "Awesome Organization")
                addRDN(BCStyle.CN, "Demo Root Certificate")
            }.build()
        val (trustKeyPair, trustCertHolder) = genTrustAnchor(SIGN_ALG, name)
        val trustCert = trustCertHolder.toCertificate()

        //
        // CA
        //
        val caSubject =
            X500NameBuilder(BCStyle.INSTANCE).apply {
                addRDN(BCStyle.C, "Utopia")
                addRDN(BCStyle.O, "Awesome Organization")
                addRDN(BCStyle.CN, "Demo Intermediate Certificate")
            }.build()
        val (caKeyPair, caCertHolder) =
            genIntermediateCertificate(
                trustCertHolder,
                trustKeyPair.private,
                SIGN_ALG,
                0,
                caSubject,
            )
        val caCert = caCertHolder.toCertificate()

        //
        // End Entity
        //
        val eeSubject =
            X500NameBuilder(BCStyle.INSTANCE).apply {
                addRDN(BCStyle.C, "Utopia")
                addRDN(BCStyle.O, "Awesome Organization")
                addRDN(BCStyle.CN, "Demo End-Entity Certificate")
            }.build()
        val (_, eeCertHolder) =
            genEndEntity(caCertHolder, caKeyPair.private, SIGN_ALG, eeSubject)
        val eeCert = eeCertHolder.toCertificate()

        return TrustedCA(trustCert, caCert) to eeCert
    }
}

@DisplayName("validateChain, when")
class X5CValidatorTest {
    private val entities = Sample.create()
    private val trustedCA = entities.first
    private val eeCertificate = entities.second

    @Test
    fun `chain contains end-entity and CA certs should succeed`() {
        // Chain contains end-entity and CA certs
        // trust contains the trust anchor cert
        val chain = nonEmptyListOf(eeCertificate, trustedCA.caCert)
        val trust = nonEmptyListOf(trustedCA.trustCert)
        assertDoesNotThrow { test(chain, trust) }
    }

    @Test
    fun `chain contains end-entity CA and Trust certs should succeed`() {
        // Chain contains end-entity, CA and Trust Anchor certs
        // trust contains the trust anchor cert
        val chain = nonEmptyListOf(
            eeCertificate,
            trustedCA.caCert,
            trustedCA.trustCert,
        )
        val trust = nonEmptyListOf(trustedCA.trustCert)

        assertDoesNotThrow { test(chain, trust) }
    }

    @Test
    fun `chain contain end-entity cert, trust contains CA and Trust certs then should succeed`() {
        // Chain contains end-entity
        // trust contains the CA and Trust Anchor certs
        val chain = nonEmptyListOf(eeCertificate)
        val trust = nonEmptyListOf(trustedCA.caCert, trustedCA.trustCert)
        assertDoesNotThrow { test(chain, trust) }
    }

    @Test
    fun `cert order in chain should not affect validation`() {
        val chain = nonEmptyListOf(trustedCA.caCert, eeCertificate)
        val trust = nonEmptyListOf(trustedCA.trustCert)
        assertThrows<CertPathValidatorException> { test(chain, trust) }
    }

    @Test
    fun `validate a partial chain should fail`() {
        val chain = nonEmptyListOf(eeCertificate)
        val trust = nonEmptyListOf(trustedCA.trustCert)
        assertThrows<CertPathValidatorException> { test(chain, trust) }
    }

    @Test
    fun `when directly trusting the CA should succeed `() {
        val chain = nonEmptyListOf(eeCertificate)
        val trust = nonEmptyListOf(trustedCA.caCert)
        assertDoesNotThrow { test(chain, trust) }
    }

    @Test
    fun `authority key identifier policy fails closed`() {
        val chain = nonEmptyListOf(eeCertificate, trustedCA.caCert)
        val expectedAki = eeCertificate.authorityKeyIdentifierBase64Url()
        val validator = X5CValidator(X5CShouldBe.AuthorityKeyIdentifier(nonEmptyListOf(expectedAki)))

        assertThrows<CertPathValidatorException> { validator.trustedOrThrow(chain) }
    }

    @Test
    fun `authority key identifier policy fails when no chain certificate matches`() {
        val chain = nonEmptyListOf(eeCertificate, trustedCA.caCert)
        val validator = X5CValidator(
            X5CShouldBe.AuthorityKeyIdentifier(nonEmptyListOf("unmatched-key-identifier")),
        )

        assertThrows<CertPathValidatorException> { validator.trustedOrThrow(chain) }
    }

    @Test
    fun `openid federation policy fails closed`() {
        val chain = nonEmptyListOf(eeCertificate, trustedCA.caCert)
        val validator = X5CValidator(
            X5CShouldBe.OpenIdFederation(
                trustAnchors = nonEmptyListOf("https://trust-anchor.example"),
                fetchEntityConfiguration = FetchOpenIdFederationEntityConfiguration { entityId ->
                    Either.Right(
                        OpenIdFederationEntityConfiguration(
                            sub = entityId,
                            authorityHints = listOf("https://trust-anchor.example"),
                        ),
                    )
                },
            ),
        )

        assertThrows<CertPathValidatorException> { validator.trustedOrThrow(chain) }
    }

    @Test
    fun `openid federation policy fails when leaf entity does not hint configured trust anchor`() {
        val chain = nonEmptyListOf(eeCertificate, trustedCA.caCert)
        val validator = X5CValidator(
            X5CShouldBe.OpenIdFederation(
                trustAnchors = nonEmptyListOf("https://trust-anchor.example"),
                fetchEntityConfiguration = FetchOpenIdFederationEntityConfiguration { entityId ->
                    Either.Right(
                        OpenIdFederationEntityConfiguration(
                            sub = entityId,
                            authorityHints = listOf("https://other-anchor.example"),
                        ),
                    )
                },
            ),
        )

        assertThrows<CertPathValidatorException> { validator.trustedOrThrow(chain) }
    }
}

private fun test(chain: Nel<X509Certificate>, trust: Nel<X509Certificate>) {
    val x5CShouldBe = X5CShouldBe.Trusted(trust)
    val validator = X5CValidator(x5CShouldBe)
    validator.trustedOrThrow(chain)
}

private fun X509Certificate.authorityKeyIdentifierBase64Url(): String {
    val extensionValue = checkNotNull(getExtensionValue(Extension.authorityKeyIdentifier.id))
    val octets = ASN1OctetString.getInstance(extensionValue).octets
    val authorityKeyIdentifier = AuthorityKeyIdentifier.getInstance(octets)
    return Base64.getUrlEncoder().withoutPadding().encodeToString(authorityKeyIdentifier.keyIdentifier)
}
