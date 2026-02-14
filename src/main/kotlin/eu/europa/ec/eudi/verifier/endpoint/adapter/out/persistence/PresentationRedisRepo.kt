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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.persistence

import arrow.core.NonEmptyList
import arrow.core.toNonEmptyListOrNull
import com.nimbusds.jose.proc.BadJOSEException
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.statium.StatusReference
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.jsonSupport
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.utils.getOrThrow
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.port.input.InitTransactionResponse
import eu.europa.ec.eudi.verifier.endpoint.port.input.ProfileTO
import eu.europa.ec.eudi.verifier.endpoint.port.input.WalletResponseAcceptedTO
import eu.europa.ec.eudi.verifier.endpoint.port.input.WalletResponseTO
import eu.europa.ec.eudi.verifier.endpoint.port.input.WalletResponseValidationError
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.*
import kotlinx.coroutines.reactor.awaitSingle
import kotlinx.coroutines.reactor.awaitSingleOrNull
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import org.slf4j.LoggerFactory
import org.springframework.data.domain.Range
import org.springframework.data.redis.core.ReactiveStringRedisTemplate
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import kotlin.time.Duration
import kotlin.time.Instant
import kotlin.time.toJavaDuration

class PresentationRedisRepo(
    private val redis: ReactiveStringRedisTemplate,
    private val clock: Clock,
    private val ttl: Duration,
) {
    private val logger = LoggerFactory.getLogger(PresentationRedisRepo::class.java)

    val loadPresentationById: LoadPresentationById by lazy {
        LoadPresentationById { transactionId ->
            redis.opsForValue()
                .get(keys.presentation(transactionId))
                .awaitSingleOrNull()
                ?.let { decodePresentation(it) }
        }
    }

    val loadPresentationByRequestId: LoadPresentationByRequestId by lazy {
        LoadPresentationByRequestId { requestId ->
            val transactionId = redis.opsForValue()
                .get(keys.requestToTransaction(requestId))
                .awaitSingleOrNull()
                ?.let { TransactionId(it) }
            transactionId?.let { loadPresentationById(it) }
                ?.takeUnless { it is Presentation.TimedOut }
        }
    }

    val loadIncompletePresentationsOlderThan: LoadIncompletePresentationsOlderThan by lazy {
        LoadIncompletePresentationsOlderThan { at ->
            val ids = redis.opsForZSet()
                .rangeByScore(keys.incompleteIndex, Range.closed(0.0, at.toEpochMilliseconds().toDouble()))
                .collectList()
                .awaitSingle()
            ids.mapNotNull { TransactionId(it) }
                .mapNotNull { loadPresentationById(it) }
                .filterNot { it is Presentation.TimedOut }
        }
    }

    val storePresentation: StorePresentation by lazy {
        StorePresentation { presentation ->
            val key = keys.presentation(presentation.id)
            val existing = redis.opsForValue().get(key).awaitSingleOrNull()?.let { decodePresentation(it) }
            if (!shouldStore(existing, presentation)) {
                return@StorePresentation
            }

            val serialized = jsonSupport.encodeToString(PresentationRecord.serializer(), presentation.toRecord())
            redis.opsForValue().set(key, serialized, ttl.toJavaDuration()).awaitSingle()
            persistRequestMapping(presentation, existing)
            persistIndexes(presentation)
            redis.expire(keys.events(presentation.id), ttl.toJavaDuration()).awaitSingleOrNull()
        }
    }

    val loadPresentationEvents: LoadPresentationEvents by lazy {
        LoadPresentationEvents { transactionId ->
            val events = redis.opsForList()
                .range(keys.events(transactionId), 0, -1)
                .collectList()
                .awaitSingle()
            events.mapNotNull { decodeEvent(it) }.toNonEmptyListOrNull()
        }
    }

    val publishPresentationEvent: PublishPresentationEvent by lazy {
        PublishPresentationEvent { event ->
            val presentationKey = keys.presentation(event.transactionId)
            val exists = redis.hasKey(presentationKey).awaitSingle()
            check(exists) { "Cannot publish event without a presentation" }
            val key = keys.events(event.transactionId)
            val payload = jsonSupport.encodeToString(PresentationEventRecord.serializer(), event.toRecord())
            redis.opsForList().rightPush(key, payload).awaitSingle()
            redis.expire(key, ttl.toJavaDuration()).awaitSingleOrNull()
        }
    }

    val deletePresentationsInitiatedBefore: DeletePresentationsInitiatedBefore by lazy {
        DeletePresentationsInitiatedBefore { at ->
            val ids = redis.opsForZSet()
                .rangeByScore(keys.initiatedIndex, Range.closed(0.0, at.toEpochMilliseconds().toDouble()))
                .collectList()
                .awaitSingle()
            ids.mapNotNull { id ->
                val transactionId = TransactionId(id)
                deletePresentation(transactionId)
                transactionId
            }
        }
    }

    private suspend fun persistRequestMapping(presentation: Presentation, existing: Presentation?) {
        val requestId = presentation.requestIdOrNull()
        val currentRequestId = existing?.requestIdOrNull()
        val requestKey = requestId ?: currentRequestId

        if (presentation is Presentation.TimedOut && requestKey != null) {
            redis.opsForValue().delete(keys.requestToTransaction(requestKey)).awaitSingleOrNull()
            redis.opsForValue().delete(keys.transactionToRequest(presentation.id)).awaitSingleOrNull()
            return
        }

        if (requestId != null) {
            redis.opsForValue()
                .set(keys.requestToTransaction(requestId), presentation.id.value, ttl.toJavaDuration())
                .awaitSingle()
            redis.opsForValue()
                .set(keys.transactionToRequest(presentation.id), requestId.value, ttl.toJavaDuration())
                .awaitSingle()
        }
    }

    private suspend fun persistIndexes(presentation: Presentation) {
        val initiatedAt = presentation.initiatedAt.toEpochMilliseconds().toDouble()
        redis.opsForZSet()
            .add(keys.initiatedIndex, presentation.id.value, initiatedAt)
            .awaitSingleOrNull()

        if (presentation is Presentation.TimedOut || presentation is Presentation.Submitted) {
            redis.opsForZSet().remove(keys.incompleteIndex, presentation.id.value).awaitSingleOrNull()
            return
        }

        val checkpoint = presentation.expiryCheckpoint().toEpochMilliseconds().toDouble()
        redis.opsForZSet()
            .add(keys.incompleteIndex, presentation.id.value, checkpoint)
            .awaitSingleOrNull()
    }

    private suspend fun deletePresentation(transactionId: TransactionId) {
        val requestId = redis.opsForValue().get(keys.transactionToRequest(transactionId)).awaitSingleOrNull()
        if (requestId != null) {
            redis.opsForValue().delete(keys.requestToTransaction(RequestId(requestId))).awaitSingleOrNull()
        }
        redis.opsForValue().delete(keys.transactionToRequest(transactionId)).awaitSingleOrNull()
        redis.opsForValue().delete(keys.presentation(transactionId)).awaitSingleOrNull()
        redis.delete(keys.events(transactionId)).awaitSingleOrNull()
        redis.opsForZSet().remove(keys.initiatedIndex, transactionId.value).awaitSingleOrNull()
        redis.opsForZSet().remove(keys.incompleteIndex, transactionId.value).awaitSingleOrNull()
    }

    private fun shouldStore(existing: Presentation?, next: Presentation): Boolean {
        if (existing == null) return true
        if (existing.isTerminal() && !next.isTerminal()) {
            logger.info("Skipping presentation update for tx={} because existing state is terminal", existing.id.value)
            return false
        }
        if (existing.isTerminal() && next.isTerminal()) {
            return false
        }
        return true
    }

    private fun decodePresentation(serialized: String): Presentation =
        jsonSupport.decodeFromString(PresentationRecord.serializer(), serialized).toDomain()

    private fun decodeEvent(serialized: String): PresentationEvent =
        jsonSupport.decodeFromString(PresentationEventRecord.serializer(), serialized).toDomain()

    private fun Presentation.requestIdOrNull(): RequestId? = when (this) {
        is Presentation.Requested -> requestId
        is Presentation.RequestObjectRetrieved -> requestId
        is Presentation.Submitted -> requestId
        is Presentation.TimedOut -> null
    }

    private fun Presentation.expiryCheckpoint(): Instant = when (this) {
        is Presentation.Requested -> initiatedAt
        is Presentation.RequestObjectRetrieved -> requestObjectRetrievedAt
        is Presentation.Submitted -> initiatedAt
        is Presentation.TimedOut -> initiatedAt
    }

    private fun Presentation.isTerminal(): Boolean = this is Presentation.Submitted || this is Presentation.TimedOut

    private object keys {
        const val initiatedIndex: String = "eudi:presentation:index:initiated"
        const val incompleteIndex: String = "eudi:presentation:index:incomplete"

        fun presentation(transactionId: TransactionId) = "eudi:presentation:${transactionId.value}"
        fun events(transactionId: TransactionId) = "eudi:presentation:events:${transactionId.value}"
        fun requestToTransaction(requestId: RequestId) = "eudi:presentation:request:${requestId.value}"
        fun transactionToRequest(transactionId: TransactionId) = "eudi:presentation:tx:${transactionId.value}:request"
    }

    @Serializable
    private sealed interface PresentationRecord {
        val id: String
        val initiatedAt: Long
    }

    @Serializable
    @SerialName("requested")
    private data class RequestedRecord(
        override val id: String,
        override val initiatedAt: Long,
        val query: DCQL,
        val transactionData: List<String>?,
        val requestId: String,
        val requestUriMethod: String,
        val nonce: String,
        val responseMode: ResponseModeRecord,
        val getWalletResponseMethod: GetWalletResponseMethodRecord,
        val issuerChain: List<String>?,
        val profile: ProfileRecord,
    ) : PresentationRecord

    @Serializable
    @SerialName("request_object_retrieved")
    private data class RequestObjectRetrievedRecord(
        override val id: String,
        override val initiatedAt: Long,
        val query: DCQL,
        val transactionData: List<String>?,
        val requestId: String,
        val requestObjectRetrievedAt: Long,
        val nonce: String,
        val responseMode: ResponseModeRecord,
        val getWalletResponseMethod: GetWalletResponseMethodRecord,
        val issuerChain: List<String>?,
        val profile: ProfileRecord,
    ) : PresentationRecord

    @Serializable
    @SerialName("submitted")
    private data class SubmittedRecord(
        override val id: String,
        override val initiatedAt: Long,
        val requestId: String,
        val requestObjectRetrievedAt: Long,
        val submittedAt: Long,
        val walletResponse: WalletResponseRecord,
        val nonce: String,
        val responseCode: String?,
        val getWalletResponseMethod: GetWalletResponseMethodRecord,
    ) : PresentationRecord

    @Serializable
    @SerialName("timed_out")
    private data class TimedOutRecord(
        override val id: String,
        override val initiatedAt: Long,
        val requestObjectRetrievedAt: Long?,
        val submittedAt: Long?,
        val timedOutAt: Long,
    ) : PresentationRecord

    @Serializable
    private sealed interface ResponseModeRecord {
    }

    @Serializable
    @SerialName("direct_post")
    private object DirectPostRecord : ResponseModeRecord

    @Serializable
    @SerialName("direct_post_jwt")
    private data class DirectPostJwtRecord(
        val jwkJson: String,
    ) : ResponseModeRecord

    @Serializable
    private sealed interface GetWalletResponseMethodRecord {
    }

    @Serializable
    @SerialName("poll")
    private object PollRecord : GetWalletResponseMethodRecord

    @Serializable
    @SerialName("redirect")
    private data class RedirectRecord(
        val redirectUriTemplate: String,
    ) : GetWalletResponseMethodRecord

    @Serializable
    private sealed interface WalletResponseRecord

    @Serializable
    @SerialName("vp_token")
    private data class VpTokenRecord(
        val verifiablePresentations: Map<String, List<VerifiablePresentationRecord>>,
    ) : WalletResponseRecord

    @Serializable
    @SerialName("error")
    private data class ErrorRecord(
        val value: String,
        val description: String?,
    ) : WalletResponseRecord

    @Serializable
    private data class VerifiablePresentationRecord(
        val format: Format,
        val value: JsonElement,
    )

    @Serializable
    private sealed interface ProfileRecord {
    }

    @Serializable
    @SerialName("openid4vp")
    private object OpenId4VpProfileRecord : ProfileRecord

    @Serializable
    @SerialName("haip")
    private object HaipProfileRecord : ProfileRecord

    @Serializable
    private sealed interface PresentationEventRecord {
        val transactionId: String
        val timestamp: Long
    }

    @Serializable
    @SerialName("transaction_initialized")
    private data class TransactionInitializedRecord(
        override val transactionId: String,
        override val timestamp: Long,
        val response: InitTransactionResponse.JwtSecuredAuthorizationRequestTO,
        val profile: ProfileTO,
    ) : PresentationEventRecord

    @Serializable
    @SerialName("request_object_retrieved")
    private data class RequestObjectRetrievedEventRecord(
        override val transactionId: String,
        override val timestamp: Long,
        val jwt: Jwt,
    ) : PresentationEventRecord

    @Serializable
    @SerialName("failed_to_retrieve_request_object")
    private data class FailedToRetrieveRequestObjectRecord(
        override val transactionId: String,
        override val timestamp: Long,
        val cause: String,
    ) : PresentationEventRecord

    @Serializable
    @SerialName("failed_to_retrieve_presentation_definition")
    private data class FailedToRetrievePresentationDefinitionRecord(
        override val transactionId: String,
        override val timestamp: Long,
        val cause: String,
    ) : PresentationEventRecord

    @Serializable
    @SerialName("wallet_response_posted")
    private data class WalletResponsePostedRecord(
        override val transactionId: String,
        override val timestamp: Long,
        val walletResponse: WalletResponseTO,
        val verifierEndpointResponse: WalletResponseAcceptedTO?,
    ) : PresentationEventRecord

    @Serializable
    @SerialName("wallet_failed_to_post_response")
    private data class WalletFailedToPostResponseRecord(
        override val transactionId: String,
        override val timestamp: Long,
        val cause: WalletResponseValidationErrorRecord,
    ) : PresentationEventRecord

    @Serializable
    @SerialName("verifier_got_wallet_response")
    private data class VerifierGotWalletResponseRecord(
        override val transactionId: String,
        override val timestamp: Long,
        val walletResponse: WalletResponseTO,
    ) : PresentationEventRecord

    @Serializable
    @SerialName("verifier_failed_to_get_wallet_response")
    private data class VerifierFailedToGetWalletResponseRecord(
        override val transactionId: String,
        override val timestamp: Long,
        val cause: String,
    ) : PresentationEventRecord

    @Serializable
    @SerialName("presentation_expired")
    private data class PresentationExpiredRecord(
        override val transactionId: String,
        override val timestamp: Long,
    ) : PresentationEventRecord

    @Serializable
    @SerialName("attestation_status_check_success")
    private data class AttestationStatusCheckSuccessfulRecord(
        override val transactionId: String,
        override val timestamp: Long,
        val statusReference: StatusReference,
    ) : PresentationEventRecord

    @Serializable
    @SerialName("attestation_status_check_failed")
    private data class AttestationStatusCheckFailedRecord(
        override val transactionId: String,
        override val timestamp: Long,
        val statusReference: StatusReference?,
        val cause: String?,
    ) : PresentationEventRecord

    @Serializable
    private sealed interface WalletResponseValidationErrorRecord

    @Serializable
    @SerialName("presentation_not_found")
    private data object PresentationNotFoundRecord : WalletResponseValidationErrorRecord

    @Serializable
    @SerialName("unexpected_response_mode")
    private data class UnexpectedResponseModeRecord(
        val requestId: String,
        val expected: String,
        val actual: String,
    ) : WalletResponseValidationErrorRecord

    @Serializable
    @SerialName("presentation_not_in_expected_state")
    private data object PresentationNotInExpectedStateRecord : WalletResponseValidationErrorRecord

    @Serializable
    @SerialName("incorrect_state")
    private data object IncorrectStateRecord : WalletResponseValidationErrorRecord

    @Serializable
    @SerialName("invalid_vp_token")
    private data class InvalidVpTokenRecord(
        val message: String,
        val cause: String?,
    ) : WalletResponseValidationErrorRecord

    @Serializable
    @SerialName("missing_vp_token")
    private data object MissingVpTokenRecord : WalletResponseValidationErrorRecord

    @Serializable
    @SerialName("required_credential_set_not_satisfied")
    private data object RequiredCredentialSetNotSatisfiedRecord : WalletResponseValidationErrorRecord

    @Serializable
    @SerialName("invalid_presentation_submission")
    private data object InvalidPresentationSubmissionRecord : WalletResponseValidationErrorRecord

    @Serializable
    @SerialName("invalid_encrypted_response")
    private data class InvalidEncryptedResponseRecord(
        val message: String,
    ) : WalletResponseValidationErrorRecord

    @Serializable
    @SerialName("haip_device_response_multi_mdoc")
    private data object DeviceResponseContainsMoreThanOneMDocRecord : WalletResponseValidationErrorRecord

    @Serializable
    @SerialName("haip_unsupported_mso_revocation")
    private data class UnsupportedMsoRevocationMechanismRecord(
        val used: Set<String>,
        val allowed: Set<String>,
    ) : WalletResponseValidationErrorRecord

    @Serializable
    @SerialName("haip_sdjwt_token_status_required")
    private data object SdJwtVcMustUseTokenStatusListRecord : WalletResponseValidationErrorRecord

    private fun Presentation.toRecord(): PresentationRecord = when (this) {
        is Presentation.Requested -> RequestedRecord(
            id = id.value,
            initiatedAt = initiatedAt.toEpochMilliseconds(),
            query = query,
            transactionData = transactionData?.map { it.base64Url },
            requestId = requestId.value,
            requestUriMethod = requestUriMethod.name,
            nonce = nonce.value,
            responseMode = responseMode.toRecord(),
            getWalletResponseMethod = getWalletResponseMethod.toRecord(),
            issuerChain = issuerChain?.let { encodeIssuerChain(it) },
            profile = profile.toRecord(),
        )
        is Presentation.RequestObjectRetrieved -> RequestObjectRetrievedRecord(
            id = id.value,
            initiatedAt = initiatedAt.toEpochMilliseconds(),
            query = query,
            transactionData = transactionData?.map { it.base64Url },
            requestId = requestId.value,
            requestObjectRetrievedAt = requestObjectRetrievedAt.toEpochMilliseconds(),
            nonce = nonce.value,
            responseMode = responseMode.toRecord(),
            getWalletResponseMethod = getWalletResponseMethod.toRecord(),
            issuerChain = issuerChain?.let { encodeIssuerChain(it) },
            profile = profile.toRecord(),
        )
        is Presentation.Submitted -> SubmittedRecord(
            id = id.value,
            initiatedAt = initiatedAt.toEpochMilliseconds(),
            requestId = requestId.value,
            requestObjectRetrievedAt = requestObjectRetrievedAt.toEpochMilliseconds(),
            submittedAt = submittedAt.toEpochMilliseconds(),
            walletResponse = walletResponse.toRecord(),
            nonce = nonce.value,
            responseCode = responseCode?.value,
            getWalletResponseMethod = getWalletResponseMethod.toRecord(),
        )
        is Presentation.TimedOut -> TimedOutRecord(
            id = id.value,
            initiatedAt = initiatedAt.toEpochMilliseconds(),
            requestObjectRetrievedAt = requestObjectRetrievedAt?.toEpochMilliseconds(),
            submittedAt = submittedAt?.toEpochMilliseconds(),
            timedOutAt = timedOutAt.toEpochMilliseconds(),
        )
    }

    private fun PresentationRecord.toDomain(): Presentation = when (this) {
        is RequestedRecord -> Presentation.Requested(
            id = TransactionId(id),
            initiatedAt = Instant.fromEpochMilliseconds(initiatedAt),
            query = query,
            transactionData = transactionData?.map { TransactionData.fromBase64Url(it).getOrThrow() }?.toNonEmptyListOrNull(),
            requestId = RequestId(requestId),
            requestUriMethod = RequestUriMethod.valueOf(requestUriMethod),
            nonce = Nonce(nonce),
            responseMode = responseMode.toDomain(),
            getWalletResponseMethod = getWalletResponseMethod.toDomain(),
            issuerChain = issuerChain?.let { decodeIssuerChain(it) },
            profile = profile.toDomain(),
        )
        is RequestObjectRetrievedRecord -> Presentation.RequestObjectRetrieved.restore(
            id = TransactionId(id),
            initiatedAt = Instant.fromEpochMilliseconds(initiatedAt),
            query = query,
            transactionData = transactionData?.map { TransactionData.fromBase64Url(it).getOrThrow() }?.toNonEmptyListOrNull(),
            requestId = RequestId(requestId),
            requestObjectRetrievedAt = Instant.fromEpochMilliseconds(requestObjectRetrievedAt),
            nonce = Nonce(nonce),
            responseMode = responseMode.toDomain(),
            getWalletResponseMethod = getWalletResponseMethod.toDomain(),
            issuerChain = issuerChain?.let { decodeIssuerChain(it) },
            profile = profile.toDomain(),
        )
        is SubmittedRecord -> Presentation.Submitted.restore(
            id = TransactionId(id),
            initiatedAt = Instant.fromEpochMilliseconds(initiatedAt),
            requestId = RequestId(requestId),
            requestObjectRetrievedAt = Instant.fromEpochMilliseconds(requestObjectRetrievedAt),
            submittedAt = Instant.fromEpochMilliseconds(submittedAt),
            walletResponse = walletResponse.toDomain(),
            nonce = Nonce(nonce),
            responseCode = responseCode?.let { ResponseCode(it) },
            getWalletResponseMethod = getWalletResponseMethod.toDomain(),
        )
        is TimedOutRecord -> Presentation.TimedOut.restore(
            id = TransactionId(id),
            initiatedAt = Instant.fromEpochMilliseconds(initiatedAt),
            requestObjectRetrievedAt = requestObjectRetrievedAt?.let { Instant.fromEpochMilliseconds(it) },
            submittedAt = submittedAt?.let { Instant.fromEpochMilliseconds(it) },
            timedOutAt = Instant.fromEpochMilliseconds(timedOutAt),
        )
    }

    private fun ResponseMode.toRecord(): ResponseModeRecord = when (this) {
        ResponseMode.DirectPost -> DirectPostRecord
        is ResponseMode.DirectPostJwt -> DirectPostJwtRecord(jwkJson = ephemeralResponseEncryptionKey.toJSONString())
    }

    private fun ResponseModeRecord.toDomain(): ResponseMode = when (this) {
        is DirectPostRecord -> ResponseMode.DirectPost
        is DirectPostJwtRecord -> ResponseMode.DirectPostJwt(JWK.parse(jwkJson))
    }

    private fun GetWalletResponseMethod.toRecord(): GetWalletResponseMethodRecord = when (this) {
        GetWalletResponseMethod.Poll -> PollRecord
        is GetWalletResponseMethod.Redirect -> RedirectRecord(redirectUriTemplate)
    }

    private fun GetWalletResponseMethodRecord.toDomain(): GetWalletResponseMethod = when (this) {
        is PollRecord -> GetWalletResponseMethod.Poll
        is RedirectRecord -> GetWalletResponseMethod.Redirect(redirectUriTemplate)
    }

    private fun WalletResponse.toRecord(): WalletResponseRecord = when (this) {
        is WalletResponse.VpToken -> VpTokenRecord(
            verifiablePresentations = verifiablePresentations.value.mapKeys { it.key.value }
                .mapValues { (_, presentations) -> presentations.map { it.toRecord() } },
        )
        is WalletResponse.Error -> ErrorRecord(value, description)
    }

    private fun WalletResponseRecord.toDomain(): WalletResponse = when (this) {
        is VpTokenRecord -> WalletResponse.VpToken(
            VerifiablePresentations(
                verifiablePresentations.mapKeys { QueryId(it.key) }
                    .mapValues { (_, list) -> list.map { it.toDomain() } },
            ),
        )
        is ErrorRecord -> WalletResponse.Error(value, description)
    }

    private fun VerifiablePresentation.toRecord(): VerifiablePresentationRecord =
        when (this) {
            is VerifiablePresentation.Str -> VerifiablePresentationRecord(format, JsonPrimitive(value))
            is VerifiablePresentation.Json -> VerifiablePresentationRecord(format, value)
        }

    private fun VerifiablePresentationRecord.toDomain(): VerifiablePresentation =
        when (value) {
            is JsonPrimitive -> VerifiablePresentation.Str(value.content, format)
            else -> VerifiablePresentation.Json(value.jsonObject, format)
        }

    private fun Profile.toRecord(): ProfileRecord = when (this) {
        Profile.OpenId4VP -> OpenId4VpProfileRecord
        Profile.HAIP -> HaipProfileRecord
    }

    private fun ProfileRecord.toDomain(): Profile = when (this) {
        is OpenId4VpProfileRecord -> Profile.OpenId4VP
        is HaipProfileRecord -> Profile.HAIP
    }

    private fun PresentationEvent.toRecord(): PresentationEventRecord = when (this) {
        is PresentationEvent.TransactionInitialized ->
            TransactionInitializedRecord(transactionId.value, timestamp.toEpochMilliseconds(), response, profile)
        is PresentationEvent.RequestObjectRetrieved ->
            RequestObjectRetrievedEventRecord(transactionId.value, timestamp.toEpochMilliseconds(), jwt)
        is PresentationEvent.FailedToRetrieveRequestObject ->
            FailedToRetrieveRequestObjectRecord(transactionId.value, timestamp.toEpochMilliseconds(), cause)
        is PresentationEvent.FailedToRetrievePresentationDefinition ->
            FailedToRetrievePresentationDefinitionRecord(transactionId.value, timestamp.toEpochMilliseconds(), cause)
        is PresentationEvent.WalletResponsePosted ->
            WalletResponsePostedRecord(transactionId.value, timestamp.toEpochMilliseconds(), walletResponse, verifierEndpointResponse)
        is PresentationEvent.WalletFailedToPostResponse ->
            WalletFailedToPostResponseRecord(transactionId.value, timestamp.toEpochMilliseconds(), cause.toRecord())
        is PresentationEvent.VerifierGotWalletResponse ->
            VerifierGotWalletResponseRecord(transactionId.value, timestamp.toEpochMilliseconds(), walletResponse)
        is PresentationEvent.VerifierFailedToGetWalletResponse ->
            VerifierFailedToGetWalletResponseRecord(transactionId.value, timestamp.toEpochMilliseconds(), cause)
        is PresentationEvent.PresentationExpired ->
            PresentationExpiredRecord(transactionId.value, timestamp.toEpochMilliseconds())
        is PresentationEvent.AttestationStatusCheckSuccessful ->
            AttestationStatusCheckSuccessfulRecord(transactionId.value, timestamp.toEpochMilliseconds(), statusReference)
        is PresentationEvent.AttestationStatusCheckFailed ->
            AttestationStatusCheckFailedRecord(transactionId.value, timestamp.toEpochMilliseconds(), statusReference, cause)
    }

    private fun PresentationEventRecord.toDomain(): PresentationEvent = when (this) {
        is TransactionInitializedRecord ->
            PresentationEvent.TransactionInitialized(TransactionId(transactionId), Instant.fromEpochMilliseconds(timestamp), response, profile)
        is RequestObjectRetrievedEventRecord ->
            PresentationEvent.RequestObjectRetrieved(TransactionId(transactionId), Instant.fromEpochMilliseconds(timestamp), jwt)
        is FailedToRetrieveRequestObjectRecord ->
            PresentationEvent.FailedToRetrieveRequestObject(TransactionId(transactionId), Instant.fromEpochMilliseconds(timestamp), cause)
        is FailedToRetrievePresentationDefinitionRecord ->
            PresentationEvent.FailedToRetrievePresentationDefinition(TransactionId(transactionId), Instant.fromEpochMilliseconds(timestamp), cause)
        is WalletResponsePostedRecord ->
            PresentationEvent.WalletResponsePosted(TransactionId(transactionId), Instant.fromEpochMilliseconds(timestamp), walletResponse, verifierEndpointResponse)
        is WalletFailedToPostResponseRecord ->
            PresentationEvent.WalletFailedToPostResponse(TransactionId(transactionId), Instant.fromEpochMilliseconds(timestamp), cause.toDomain())
        is VerifierGotWalletResponseRecord ->
            PresentationEvent.VerifierGotWalletResponse(TransactionId(transactionId), Instant.fromEpochMilliseconds(timestamp), walletResponse)
        is VerifierFailedToGetWalletResponseRecord ->
            PresentationEvent.VerifierFailedToGetWalletResponse(TransactionId(transactionId), Instant.fromEpochMilliseconds(timestamp), cause)
        is PresentationExpiredRecord ->
            PresentationEvent.PresentationExpired(TransactionId(transactionId), Instant.fromEpochMilliseconds(timestamp))
        is AttestationStatusCheckSuccessfulRecord ->
            PresentationEvent.AttestationStatusCheckSuccessful(TransactionId(transactionId), Instant.fromEpochMilliseconds(timestamp), statusReference)
        is AttestationStatusCheckFailedRecord ->
            PresentationEvent.AttestationStatusCheckFailed(TransactionId(transactionId), Instant.fromEpochMilliseconds(timestamp), statusReference, cause)
    }

    private fun WalletResponseValidationError.toRecord(): WalletResponseValidationErrorRecord = when (this) {
        WalletResponseValidationError.PresentationNotFound -> PresentationNotFoundRecord
        is WalletResponseValidationError.UnexpectedResponseMode ->
            UnexpectedResponseModeRecord(requestId.value, expected.name, actual.name)
        WalletResponseValidationError.PresentationNotInExpectedState -> PresentationNotInExpectedStateRecord
        WalletResponseValidationError.IncorrectState -> IncorrectStateRecord
        is WalletResponseValidationError.InvalidVpToken ->
            InvalidVpTokenRecord(message, cause?.message)
        WalletResponseValidationError.MissingVpToken -> MissingVpTokenRecord
        WalletResponseValidationError.RequiredCredentialSetNotSatisfied -> RequiredCredentialSetNotSatisfiedRecord
        WalletResponseValidationError.InvalidPresentationSubmission -> InvalidPresentationSubmissionRecord
        is WalletResponseValidationError.InvalidEncryptedResponse ->
            InvalidEncryptedResponseRecord(error.message ?: "Invalid encrypted response")
        WalletResponseValidationError.HAIPValidationError.DeviceResponseContainsMoreThanOneMDoc ->
            DeviceResponseContainsMoreThanOneMDocRecord
        is WalletResponseValidationError.HAIPValidationError.UnsupportedMsoRevocationMechanism ->
            UnsupportedMsoRevocationMechanismRecord(used, allowed)
        WalletResponseValidationError.HAIPValidationError.SdJwtVcMustUseTokenStatusList ->
            SdJwtVcMustUseTokenStatusListRecord
    }

    private fun WalletResponseValidationErrorRecord.toDomain(): WalletResponseValidationError = when (this) {
        PresentationNotFoundRecord -> WalletResponseValidationError.PresentationNotFound
        is UnexpectedResponseModeRecord ->
            WalletResponseValidationError.UnexpectedResponseMode(
                RequestId(requestId),
                ResponseModeOption.valueOf(expected),
                ResponseModeOption.valueOf(actual),
            )
        PresentationNotInExpectedStateRecord -> WalletResponseValidationError.PresentationNotInExpectedState
        IncorrectStateRecord -> WalletResponseValidationError.IncorrectState
        is InvalidVpTokenRecord -> WalletResponseValidationError.InvalidVpToken(message, cause?.let { Throwable(it) })
        MissingVpTokenRecord -> WalletResponseValidationError.MissingVpToken
        RequiredCredentialSetNotSatisfiedRecord -> WalletResponseValidationError.RequiredCredentialSetNotSatisfied
        InvalidPresentationSubmissionRecord -> WalletResponseValidationError.InvalidPresentationSubmission
        is InvalidEncryptedResponseRecord -> WalletResponseValidationError.InvalidEncryptedResponse(BadJOSEException(message))
        DeviceResponseContainsMoreThanOneMDocRecord -> WalletResponseValidationError.HAIPValidationError.DeviceResponseContainsMoreThanOneMDoc
        is UnsupportedMsoRevocationMechanismRecord ->
            WalletResponseValidationError.HAIPValidationError.UnsupportedMsoRevocationMechanism(used, allowed)
        SdJwtVcMustUseTokenStatusListRecord -> WalletResponseValidationError.HAIPValidationError.SdJwtVcMustUseTokenStatusList
    }

    private fun encodeIssuerChain(chain: NonEmptyList<X509Certificate>): List<String> =
        chain.map { Base64.getEncoder().encodeToString(it.encoded) }

    private fun decodeIssuerChain(encoded: List<String>): NonEmptyList<X509Certificate>? {
        val certFactory = CertificateFactory.getInstance("X.509")
        val certs = encoded.mapNotNull { encodedCert ->
            val bytes = Base64.getDecoder().decode(encodedCert)
            certFactory.generateCertificate(ByteArrayInputStream(bytes)) as? X509Certificate
        }
        return certs.toNonEmptyListOrNull()
    }
}
