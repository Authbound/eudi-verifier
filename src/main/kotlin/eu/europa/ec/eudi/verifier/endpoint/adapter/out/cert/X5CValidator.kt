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
import arrow.core.NonEmptyList
import arrow.core.toNonEmptyListOrNull
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier
import org.bouncycastle.asn1.x509.Extension
import java.security.KeyStore
import java.security.cert.*
import java.util.Base64
import javax.naming.ldap.LdapName

typealias ConfigurePKIXParameters = PKIXParameters.() -> Unit

internal val SkipRevocation: ConfigurePKIXParameters = { isRevocationEnabled = false }

data class OpenIdFederationEntityConfiguration(
    val sub: String?,
    val authorityHints: List<String>,
)

fun interface FetchOpenIdFederationEntityConfiguration {
    operator fun invoke(entityId: String): Either<Throwable, OpenIdFederationEntityConfiguration>
}

/**
 * Options about [certificate chain validator][X5CValidator]
 */
sealed interface X5CShouldBe {

    /**
     * The chain should be trusted
     *
     * @param rootCACertificates list of trusted root CA certificates. To be used as trust anchors
     * @param customizePKIX a way to parameterize [PKIXParameters]. If not provided, revocation checks are disabled
     */
    data class Trusted(
        val rootCACertificates: NonEmptyList<X509Certificate>,
        val customizePKIX: ConfigurePKIXParameters = SkipRevocation,
    ) : X5CShouldBe

    /**
     * The chain should contain at least one AuthorityKeyIdentifier whose raw key identifier matches one of the
     * base64url-encoded values requested through DCQL trusted_authorities type "aki".
     */
    data class AuthorityKeyIdentifier(
        val keyIdentifiers: NonEmptyList<String>,
    ) : X5CShouldBe

    /**
     * The chain's leaf certificate should identify a federation entity that either is one of the configured trust
     * anchors or publishes an OpenID Federation entity configuration with authority_hints pointing at one of them.
     */
    data class OpenIdFederation(
        val trustAnchors: NonEmptyList<String>,
        val fetchEntityConfiguration: FetchOpenIdFederationEntityConfiguration,
    ) : X5CShouldBe

    /**
     * The chain should satisfy at least one listed trust policy.
     */
    data class OneOf(
        val policies: NonEmptyList<X5CShouldBe>,
    ) : X5CShouldBe

    /**
     * The chain will not be checked
     */
    data object Ignored : X5CShouldBe

    fun caCertificates(): List<X509Certificate> =
        when (this) {
            Ignored -> emptyList()
            is AuthorityKeyIdentifier -> emptyList()
            is OpenIdFederation -> emptyList()
            is Trusted -> rootCACertificates
            is OneOf -> policies.toList().flatMap { it.caCertificates() }
        }

    companion object {
        operator fun invoke(
            rootCACertificates: List<X509Certificate>,
            customizePKIX: ConfigurePKIXParameters = SkipRevocation,
        ): X5CShouldBe =
            when (val nel = rootCACertificates.toNonEmptyListOrNull()) {
                null -> Ignored
                else -> Trusted(nel, customizePKIX)
            }

        fun fromKeystore(
            trustedCAsKeyStore: KeyStore,
            customizePKIX: ConfigurePKIXParameters = SkipRevocation,
        ): X5CShouldBe {
            val trustedRootCAs = trustedCAs(trustedCAsKeyStore)
            return X5CShouldBe(trustedRootCAs, customizePKIX)
        }

        internal fun trustedCAs(keystore: KeyStore): List<X509Certificate> {
            fun x509(alias: String) =
                alias.takeIf(keystore::isCertificateEntry)
                    ?.let(keystore::getCertificate) as? X509Certificate

            return buildList {
                for (alias in keystore.aliases()) {
                    x509(alias)?.let(::add)
                }
            }
        }
    }
}

class X5CValidator(private val x5CShouldBe: X5CShouldBe) {

    fun ensureTrusted(
        chain: Nel<X509Certificate>,
    ): Either<CertPathValidatorException, Nel<X509Certificate>> =
        Either.catchOrThrow {
            trustedOrThrow(chain)
            chain
        }

    @Throws(CertPathValidatorException::class)
    fun trustedOrThrow(chain: Nel<X509Certificate>) {
        when (x5CShouldBe) {
            X5CShouldBe.Ignored -> Unit // Do nothing
            is X5CShouldBe.AuthorityKeyIdentifier ->
                throw CertPathValidatorException("AuthorityKeyIdentifier trust policy is unsupported")
            is X5CShouldBe.OpenIdFederation ->
                throw CertPathValidatorException("OpenID Federation trust policy is unsupported")
            is X5CShouldBe.OneOf -> trustedOrThrow(chain, x5CShouldBe)
            is X5CShouldBe.Trusted -> {
                trustedOrThrow(chain, x5CShouldBe)
            }
        }
    }
}

@Throws(CertPathValidatorException::class)
private fun trustedOrThrow(
    chain: Nel<X509Certificate>,
    federation: X5CShouldBe.OpenIdFederation,
) {
    val entityId = chain.head.openIdFederationEntityId()
        ?.normalizeOpenIdFederationEntityId()
        ?: throw CertPathValidatorException("Certificate chain leaf does not identify an OpenID Federation entity")

    val trustAnchors = federation.trustAnchors
        .map { it.normalizeOpenIdFederationEntityId() }
        .toSet()
    if (entityId in trustAnchors) {
        return
    }

    val entityConfiguration = federation.fetchEntityConfiguration(entityId)
        .fold(
            ifLeft = { error ->
                throw CertPathValidatorException("Could not fetch OpenID Federation entity configuration", error)
            },
            ifRight = { it },
        )

    val subjectMatches = entityConfiguration.sub
        ?.normalizeOpenIdFederationEntityId()
        ?.let { it == entityId }
        ?: true
    val hints = entityConfiguration.authorityHints
        .map { it.normalizeOpenIdFederationEntityId() }
        .toSet()
    if (!subjectMatches || hints.none { it in trustAnchors }) {
        throw CertPathValidatorException("OpenID Federation entity does not chain to a configured trust anchor")
    }
}

@Throws(CertPathValidatorException::class)
private fun trustedOrThrow(
    chain: Nel<X509Certificate>,
    trusted: X5CShouldBe.Trusted,
) {
    val factory = CertificateFactory.getInstance("X.509")
    val certPath = factory.generateCertPath(chain)

    val pkixParameters = trusted.asPkixParameters()
    val validator = CertPathValidator.getInstance("PKIX")

    validator.validate(certPath, pkixParameters)
}

@Throws(CertPathValidatorException::class)
private fun trustedOrThrow(
    chain: Nel<X509Certificate>,
    authorityKeyIdentifier: X5CShouldBe.AuthorityKeyIdentifier,
) {
    val expectedKeyIdentifiers = authorityKeyIdentifier.keyIdentifiers
        .map { it.canonicalBase64UrlAuthorityKeyIdentifier() }
        .toSet()
    val actualKeyIdentifiers = chain
        .mapNotNull { it.authorityKeyIdentifierBase64Url() }
        .toSet()

    if (actualKeyIdentifiers.none { it in expectedKeyIdentifiers }) {
        throw CertPathValidatorException("Certificate chain does not contain a matching AuthorityKeyIdentifier")
    }
}

@Throws(CertPathValidatorException::class)
private fun trustedOrThrow(
    chain: Nel<X509Certificate>,
    oneOf: X5CShouldBe.OneOf,
) {
    val failures = oneOf.policies.mapNotNull { policy ->
        Either.catch {
            X5CValidator(policy).trustedOrThrow(chain)
        }.fold(ifLeft = { it }, ifRight = { null })
    }
    if (failures.size == oneOf.policies.size) {
        throw CertPathValidatorException(
            "Certificate chain does not match any trusted authority policy",
            failures.firstOrNull(),
        )
    }
}

private fun X5CShouldBe.Trusted.asPkixParameters(): PKIXParameters {
    val trust = rootCACertificates.map { cert -> TrustAnchor(cert, null) }.toSet()
    return PKIXParameters(trust).apply(customizePKIX)
}

private fun String.canonicalBase64UrlAuthorityKeyIdentifier(): String =
    try {
        authorityKeyIdentifierBase64UrlEncoder.encodeToString(Base64.getUrlDecoder().decode(this))
    } catch (e: IllegalArgumentException) {
        throw CertPathValidatorException("Invalid base64url AuthorityKeyIdentifier value", e)
    }

private fun X509Certificate.authorityKeyIdentifierBase64Url(): String? {
    val extensionValue = getExtensionValue(Extension.authorityKeyIdentifier.id) ?: return null
    return Either.catch {
        val octets = ASN1OctetString.getInstance(extensionValue).octets
        val authorityKeyIdentifier = AuthorityKeyIdentifier.getInstance(octets)
        authorityKeyIdentifier.keyIdentifier?.let(authorityKeyIdentifierBase64UrlEncoder::encodeToString)
    }.getOrNull()
}

private val authorityKeyIdentifierBase64UrlEncoder = Base64.getUrlEncoder().withoutPadding()

private const val SUBJECT_ALT_NAME_URI = 6

private fun X509Certificate.openIdFederationEntityId(): String? =
    uriSubjectAlternativeNames().firstOrNull()
        ?: commonName()

private fun X509Certificate.uriSubjectAlternativeNames(): List<String> =
    subjectAlternativeNames
        ?.mapNotNull { san ->
            val type = san.getOrNull(0) as? Int
            val value = san.getOrNull(1) as? String
            value?.takeIf { type == SUBJECT_ALT_NAME_URI }
        }
        .orEmpty()

private fun X509Certificate.commonName(): String? =
    runCatching {
        LdapName(subjectX500Principal.name)
            .rdns
            .firstOrNull { it.type.equals("CN", ignoreCase = true) }
            ?.value
            ?.toString()
    }.getOrNull()

private fun String.normalizeOpenIdFederationEntityId(): String =
    trim().removeSuffix("/")
