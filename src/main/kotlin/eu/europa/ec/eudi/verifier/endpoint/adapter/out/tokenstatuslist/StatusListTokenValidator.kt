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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.tokenstatuslist

import arrow.core.raise.catch
import arrow.core.toNonEmptyListOrNull
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jose.util.Base64
import eu.europa.ec.eudi.sdjwt.SdJwtAndKbJwt
import eu.europa.ec.eudi.sdjwt.SdJwtVcSpec
import eu.europa.ec.eudi.statium.GetStatus
import eu.europa.ec.eudi.statium.GetStatusListToken
import eu.europa.ec.eudi.statium.Status
import eu.europa.ec.eudi.statium.StatusListTokenClaims
import eu.europa.ec.eudi.statium.StatusReference
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.tokenStatusListReference
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.sdjwtvc.statusReference
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.ProvideTrustSource
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.X5CShouldBe
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.X5CValidator
import eu.europa.ec.eudi.verifier.endpoint.domain.Clock
import eu.europa.ec.eudi.verifier.endpoint.domain.Clock.Companion.asKotlinClock
import eu.europa.ec.eudi.verifier.endpoint.domain.TransactionId
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PublishPresentationEvent
import id.walt.mdoc.doc.MDoc
import io.ktor.client.*
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Date
import kotlin.time.Instant
import kotlin.time.toJavaInstant

data class StatusCheckException(val reason: String, val causedBy: Throwable) : Exception(reason, causedBy)

class StatusListTokenValidator(
    private val httpClient: HttpClient,
    private val clock: Clock,
    private val publishPresentationEvent: PublishPresentationEvent,
    private val provideTrustSource: ProvideTrustSource,
    private val cache: StatusListTokenCache = NoopStatusListTokenCache,
) {

    suspend fun validate(sdJwtVc: SdJwtAndKbJwt<SignedJWT>, transactionId: TransactionId?) {
        val statusReference = try {
            sdJwtVc.statusReference()
        } catch (error: Throwable) {
            return failStatusReference("Invalid status_list reference in SD-JWT VC", transactionId, error)
        } ?: return failStatusReference("Missing status_list reference in SD-JWT VC", transactionId)
        val (sdJwt, _) = sdJwtVc
        val vct = try {
            sdJwt.jwt.jwtClaimsSet.getStringClaim(SdJwtVcSpec.VCT)
        } catch (error: Throwable) {
            return failStatusReference("Invalid vct claim in SD-JWT VC", transactionId, error)
        } ?: return failStatusReference("Missing vct claim in SD-JWT VC", transactionId)
        val x5cShouldBe = resolveTrustSource(vct, transactionId)
        statusReference.validate(transactionId, x5cShouldBe)
    }

    suspend fun validate(mdoc: MDoc, transactionId: TransactionId?) {
        val statusReference = try {
            mdoc.issuerSigned.issuerAuth?.tokenStatusListReference()
        } catch (error: Throwable) {
            return failStatusReference("Invalid status_list reference in MSO mdoc", transactionId, error)
        } ?: return failStatusReference("Missing status_list reference in MSO mdoc", transactionId)
        val x5cShouldBe = resolveTrustSource(mdoc.docType.value, transactionId)
        statusReference.validate(transactionId, x5cShouldBe)
    }

    private suspend fun resolveTrustSource(type: String, transactionId: TransactionId?): X5CShouldBe {
        val x5cShouldBe = provideTrustSource(type)
        if (x5cShouldBe == null) {
            failStatusReference("No trust source configured for '$type'", transactionId)
        }
        return x5cShouldBe
    }

    private suspend fun StatusReference.validate(
        transactionId: TransactionId?,
        x5cShouldBe: X5CShouldBe,
    ) {
        catch({
            val currentStatus = with(getStatus(x5cShouldBe)) { currentStatus().getOrThrow() }
            require(currentStatus == Status.Valid) { "Attestation status expected to be VALID but is $currentStatus" }
            transactionId?.let { logStatusCheckSuccess(it, this) }
        }) { error ->
            transactionId?.let { logStatusCheckFailed(it, this, error) }
            throw StatusCheckException("Attestation status check failed, ${error.message}", error)
        }
    }

    private fun getStatus(x5cShouldBe: X5CShouldBe): GetStatus {
        val getStatusListToken: GetStatusListToken = GetStatusListToken.usingJwt(
            clock = clock.asKotlinClock(),
            httpClient = httpClient,
            verifyStatusListTokenSignature = { token, at ->
                verifyStatusListTokenSignature(token, at, x5cShouldBe)
            },
        )
        val cachedGetStatusListToken = CachedGetStatusListToken(getStatusListToken, cache)
        return GetStatus(cachedGetStatusListToken)
    }

    private suspend fun logStatusCheckSuccess(transactionId: TransactionId, statusReference: StatusReference) {
        val event = PresentationEvent.AttestationStatusCheckSuccessful(transactionId, clock.now(), statusReference)
        publishPresentationEvent(event)
    }

    private suspend fun logStatusCheckFailed(transactionId: TransactionId, statusReference: StatusReference?, error: Throwable) {
        val event = PresentationEvent.AttestationStatusCheckFailed(transactionId, clock.now(), statusReference, error.message)
        publishPresentationEvent(event)
    }

    private suspend fun failStatusReference(message: String, transactionId: TransactionId?, cause: Throwable? = null): Nothing {
        val error = cause ?: IllegalStateException(message)
        transactionId?.let { logStatusCheckFailed(it, null, error) }
        throw StatusCheckException(message, error)
    }

    private fun verifyStatusListTokenSignature(
        statusListToken: String,
        at: Instant,
        x5cShouldBe: X5CShouldBe,
    ): Result<Unit> = runCatching {
        val signedJwt = SignedJWT.parse(statusListToken)
        val chain = signedJwt.header.x509CertChain?.map(::decodeCertificate)
            ?.toNonEmptyListOrNull()
            ?: error("Missing x5c certificate chain in status list token header")
        val x5cValidator = X5CValidator(x5cShouldBe)
        x5cValidator.trustedOrThrow(chain)
        val validationDate = Date.from(at.toJavaInstant())
        chain.forEach { it.checkValidity(validationDate) }
        val verifier = DefaultJWSVerifierFactory().createJWSVerifier(signedJwt.header, chain.first().publicKey)
        check(signedJwt.verify(verifier)) { "Invalid status list token signature" }
    }

    private fun decodeCertificate(encoded: Base64): X509Certificate {
        val factory = CertificateFactory.getInstance("X.509")
        return factory.generateCertificate(encoded.decode().inputStream()) as X509Certificate
    }

    private class CachedGetStatusListToken(
        private val delegate: GetStatusListToken,
        private val cache: StatusListTokenCache,
    ) : GetStatusListToken {
        override suspend fun invoke(uri: String, at: Instant?): Result<StatusListTokenClaims> =
            try {
                val cached = cache.get(uri, at)
                if (cached != null) {
                    Result.success(cached)
                } else {
                    val claims = delegate(uri, at).getOrThrow()
                    cache.put(uri, at, claims)
                    Result.success(claims)
                }
            } catch (error: Throwable) {
                Result.failure(error)
            }
    }
}
