package eu.europa.ec.eudi.verifier.endpoint.adapter.out.persistence

import arrow.core.NonEmptyList
import arrow.core.nonEmptyListOf
import arrow.core.toNonEmptyListOrNull
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import com.nimbusds.jose.proc.BadJOSEException
import eu.europa.ec.eudi.prex.PresentationDefinition
import eu.europa.ec.eudi.prex.PresentationSubmission
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose.PresentationDefinitionJackson
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.jsonSupport
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.port.input.JwtSecuredAuthorizationRequestTO
import eu.europa.ec.eudi.verifier.endpoint.port.input.WalletResponseAcceptedTO
import eu.europa.ec.eudi.verifier.endpoint.port.input.WalletResponseTO
import eu.europa.ec.eudi.verifier.endpoint.port.input.WalletResponseValidationError
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.*
import kotlinx.coroutines.reactor.awaitSingle
import kotlinx.coroutines.reactor.awaitSingleOrNull
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import org.slf4j.LoggerFactory
import org.springframework.data.domain.Range
import org.springframework.data.redis.connection.Limit
import org.springframework.data.redis.core.ReactiveStringRedisTemplate
import java.time.Duration
import java.time.Instant

private val logger = LoggerFactory.getLogger(PresentationRedisRepo::class.java)
private val objectMapper = jacksonObjectMapper()

private val json = Json {
    ignoreUnknownKeys = true
    classDiscriminator = "type"
}

class PresentationRedisRepo(
    private val redis: ReactiveStringRedisTemplate,
    private val presentationDefinitionByReference: EmbedOption.ByReference<RequestId>,
    private val ttl: Duration,
) {

    val loadPresentationById: LoadPresentationById by lazy {
        LoadPresentationById { presentationId ->
            loadPresentation(presentationId)
        }
    }

    val loadPresentationByRequestId: LoadPresentationByRequestId by lazy {
        LoadPresentationByRequestId { requestId ->
            val txId = redis.opsForValue()
                .get(requestIndexKey(requestId))
                .awaitSingleOrNull()
                ?: return@LoadPresentationByRequestId null

            loadPresentation(TransactionId(txId))
        }
    }

    val loadIncompletePresentationsOlderThan: LoadIncompletePresentationsOlderThan by lazy {
        LoadIncompletePresentationsOlderThan { at ->
            val cutoff = at.toEpochMilli().toDouble()
            val ids = redis.opsForZSet()
                .rangeByScore(
                    indexIncompleteKey(),
                    Range.closed(Double.NEGATIVE_INFINITY, cutoff),
                    Limit.unlimited(),
                )
                .collectList()
                .awaitSingle()

            ids.mapNotNull { id -> loadPresentation(TransactionId(id)) }
        }
    }

    val storePresentation: StorePresentation by lazy {
        StorePresentation { presentation ->
            val existing = if (presentation is Presentation.Requested) null else {
                loadPresentationRecord(presentation.id)
            }
            val record = presentation.toRecord(existing)
            val serialized = json.encodeToString(PresentationRecord.serializer(), record)
            val key = presentationKey(presentation.id)

            redis.opsForValue().set(key, serialized, ttl).awaitSingle()
            updateIndexes(presentation)
            updateRequestMapping(presentation, record)
        }
    }

    val loadPresentationEvents: LoadPresentationEvents by lazy {
        LoadPresentationEvents { transactionId ->
            val key = eventsKey(transactionId)
            val events = redis.opsForList()
                .range(key, 0, -1)
                .collectList()
                .awaitSingle()
                .mapNotNull { decodeEvent(it) }

            events.toNonEmptyListOrNull()
        }
    }

    val publishPresentationEvent: PublishPresentationEvent by lazy {
        PublishPresentationEvent { event ->
            log(event)
            ensurePresentationExists(event.transactionId)
            val record = event.toRecord()
            val serialized = json.encodeToString(PresentationEventRecord.serializer(), record)
            val key = eventsKey(event.transactionId)

            redis.opsForList().rightPush(key, serialized).awaitSingle()
            redis.expire(key, ttl).awaitSingle()
        }
    }

    val deletePresentationsInitiatedBefore: DeletePresentationsInitiatedBefore by lazy {
        DeletePresentationsInitiatedBefore { at ->
            val cutoff = at.toEpochMilli().toDouble()
            val ids = redis.opsForZSet()
                .rangeByScore(
                    indexInitiatedKey(),
                    Range.closed(Double.NEGATIVE_INFINITY, cutoff),
                    Limit.unlimited(),
                )
                .collectList()
                .awaitSingle()

            if (ids.isEmpty()) return@DeletePresentationsInitiatedBefore emptyList()

            ids.forEach { id ->
                val txId = TransactionId(id)
                val requestId = redis.opsForValue().get(transactionRequestKey(txId)).awaitSingleOrNull()
                val keys = buildList<String> {
                    add(presentationKey(txId))
                    add(eventsKey(txId))
                    add(transactionRequestKey(txId))
                    if (requestId != null) add(requestIndexKey(RequestId(requestId)))
                }
                redis.delete(*keys.toTypedArray()).awaitSingle()
            }

            redis.opsForZSet().remove(indexInitiatedKey(), *ids.toTypedArray()).awaitSingle()
            redis.opsForZSet().remove(indexIncompleteKey(), *ids.toTypedArray()).awaitSingle()

            ids.map { TransactionId(it) }
        }
    }

    private suspend fun loadPresentationRecord(presentationId: TransactionId): PresentationRecord? {
        val key = presentationKey(presentationId)
        val payload = redis.opsForValue().get(key).awaitSingleOrNull() ?: return null
        return json.decodeFromString(PresentationRecord.serializer(), payload)
    }

    private suspend fun loadPresentation(presentationId: TransactionId): Presentation? {
        val record = loadPresentationRecord(presentationId) ?: return null
        return record.toDomain(presentationDefinitionByReference)
    }

    private suspend fun updateIndexes(presentation: Presentation) {
        val id = presentation.id.value
        redis.opsForZSet()
            .add(indexInitiatedKey(), id, presentation.initiatedAt.toEpochMilli().toDouble())
            .awaitSingle()

        val incompleteScore = presentation.incompleteScore()
        if (incompleteScore == null) {
            redis.opsForZSet().remove(indexIncompleteKey(), id).awaitSingle()
        } else {
            redis.opsForZSet().add(indexIncompleteKey(), id, incompleteScore).awaitSingle()
        }
    }

    private suspend fun updateRequestMapping(presentation: Presentation, record: PresentationRecord) {
        val requestId = presentation.requestIdOrNull() ?: RequestId(record.requestId)

        redis.opsForValue()
            .set(requestIndexKey(requestId), presentation.id.value, ttl)
            .awaitSingle()
        redis.opsForValue()
            .set(transactionRequestKey(presentation.id), requestId.value, ttl)
            .awaitSingle()
    }

    private suspend fun ensurePresentationExists(transactionId: TransactionId) {
        val exists = redis.hasKey(presentationKey(transactionId)).awaitSingle()
        check(exists) { "Cannot publish event without a presentation" }
    }

    private fun decodeEvent(payload: String): PresentationEvent? = runCatching {
        val record = json.decodeFromString(PresentationEventRecord.serializer(), payload)
        record.toDomain()
    }.getOrNull()

    private fun presentationKey(transactionId: TransactionId) = "eudi:presentation:${transactionId.value}"

    private fun requestIndexKey(requestId: RequestId) = "eudi:presentation:request:${requestId.value}"

    private fun transactionRequestKey(transactionId: TransactionId) =
        "eudi:presentation:tx:${transactionId.value}:request"

    private fun eventsKey(transactionId: TransactionId) = "eudi:presentation:events:${transactionId.value}"

    private fun indexInitiatedKey() = "eudi:presentation:index:initiated"

    private fun indexIncompleteKey() = "eudi:presentation:index:incomplete"
}

private fun Presentation.requestIdOrNull(): RequestId? = when (this) {
    is Presentation.Requested -> requestId
    is Presentation.RequestObjectRetrieved -> requestId
    is Presentation.Submitted -> requestId
    is Presentation.TimedOut -> null
}

private fun Presentation.incompleteScore(): Double? = when (this) {
    is Presentation.Requested -> initiatedAt.toEpochMilli().toDouble()
    is Presentation.RequestObjectRetrieved -> requestObjectRetrievedAt.toEpochMilli().toDouble()
    is Presentation.Submitted -> initiatedAt.toEpochMilli().toDouble()
    is Presentation.TimedOut -> null
}

@Serializable
private data class PresentationRecord(
    val id: String,
    val initiatedAt: Long,
    val type: PresentationTypeRecord,
    val requestId: String,
    val requestUriMethod: String,
    val nonce: String,
    val jarmEncryptionEphemeralKey: String?,
    val responseMode: String,
    val presentationDefinitionMode: String,
    val getWalletResponseMethod: WalletResponseMethodRecord,
    val state: PresentationStateRecord,
)

private fun Presentation.toRecord(existing: PresentationRecord? = null): PresentationRecord {
    val baseRequestId = requestIdOrNull()?.value ?: existing?.requestId
    val baseRequestUriMethod = when (this) {
        is Presentation.Requested -> requestUriMethod.name
        else -> existing?.requestUriMethod
    }
    val baseNonce = when (this) {
        is Presentation.Requested -> nonce.value
        is Presentation.RequestObjectRetrieved -> nonce.value
        is Presentation.Submitted -> nonce.value
        is Presentation.TimedOut -> existing?.nonce
    }
    val baseJarmKey = when (this) {
        is Presentation.Requested -> jarmEncryptionEphemeralKey?.value
        is Presentation.RequestObjectRetrieved -> ephemeralEcPrivateKey?.value
        else -> existing?.jarmEncryptionEphemeralKey
    }
    val baseResponseMode = when (this) {
        is Presentation.Requested -> responseMode.name
        is Presentation.RequestObjectRetrieved -> responseMode.name
        else -> existing?.responseMode
    }
    val basePresentationDefinitionMode = when (this) {
        is Presentation.Requested -> when (presentationDefinitionMode) {
            is EmbedOption.ByReference -> "by_reference"
            is EmbedOption.ByValue -> "by_value"
        }
        else -> existing?.presentationDefinitionMode
    }
    val baseWalletResponseMethod = when (this) {
        is Presentation.Requested -> getWalletResponseMethod.toRecord()
        is Presentation.RequestObjectRetrieved -> getWalletResponseMethod.toRecord()
        else -> existing?.getWalletResponseMethod
    }

    requireNotNull(baseRequestId) { "Missing requestId for presentation ${id.value}" }
    requireNotNull(baseRequestUriMethod) { "Missing requestUriMethod for presentation ${id.value}" }
    requireNotNull(baseNonce) { "Missing nonce for presentation ${id.value}" }
    requireNotNull(baseResponseMode) { "Missing responseMode for presentation ${id.value}" }
    requireNotNull(basePresentationDefinitionMode) { "Missing presentationDefinitionMode for presentation ${id.value}" }
    requireNotNull(baseWalletResponseMethod) { "Missing wallet response method for presentation ${id.value}" }

    return PresentationRecord(
        id = id.value,
        initiatedAt = initiatedAt.toEpochMilli(),
        type = type.toRecord(),
        requestId = baseRequestId,
        requestUriMethod = baseRequestUriMethod,
        nonce = baseNonce,
        jarmEncryptionEphemeralKey = baseJarmKey,
        responseMode = baseResponseMode,
        presentationDefinitionMode = basePresentationDefinitionMode,
        getWalletResponseMethod = baseWalletResponseMethod,
        state = toStateRecord(),
    )
}

private fun Presentation.toStateRecord(): PresentationStateRecord = when (this) {
    is Presentation.Requested -> PresentationStateRecord.Requested
    is Presentation.RequestObjectRetrieved -> PresentationStateRecord.RequestObjectRetrieved(
        requestObjectRetrievedAt = requestObjectRetrievedAt.toEpochMilli(),
        ephemeralEcPrivateKey = ephemeralEcPrivateKey?.value,
    )
    is Presentation.Submitted -> PresentationStateRecord.Submitted(
        requestObjectRetrievedAt = requestObjectRetrievedAt.toEpochMilli(),
        submittedAt = submittedAt.toEpochMilli(),
        walletResponse = walletResponse.toRecord(),
        responseCode = responseCode?.value,
    )
    is Presentation.TimedOut -> PresentationStateRecord.TimedOut(
        requestObjectRetrievedAt = requestObjectRetrievedAt?.toEpochMilli(),
        submittedAt = submittedAt?.toEpochMilli(),
        timedOutAt = timedOutAt.toEpochMilli(),
    )
}

private fun PresentationRecord.toDomain(
    presentationDefinitionByReference: EmbedOption.ByReference<RequestId>,
): Presentation {
    val requested = Presentation.Requested(
        id = TransactionId(id),
        initiatedAt = Instant.ofEpochMilli(initiatedAt),
        type = type.toDomain(),
        requestId = RequestId(requestId),
        requestUriMethod = RequestUriMethod.valueOf(requestUriMethod),
        nonce = Nonce(nonce),
        jarmEncryptionEphemeralKey = jarmEncryptionEphemeralKey?.let { EphemeralEncryptionKeyPairJWK(it) },
        responseMode = ResponseModeOption.valueOf(responseMode),
        presentationDefinitionMode = when (presentationDefinitionMode) {
            "by_reference" -> presentationDefinitionByReference
            else -> EmbedOption.ByValue
        },
        getWalletResponseMethod = getWalletResponseMethod.toDomain(),
    )

    return when (val stored = state) {
        is PresentationStateRecord.Requested -> requested
        is PresentationStateRecord.RequestObjectRetrieved ->
            Presentation.RequestObjectRetrieved.requestObjectRetrieved(
                requested,
                Instant.ofEpochMilli(stored.requestObjectRetrievedAt),
            ).getOrThrow()
        is PresentationStateRecord.Submitted -> {
            val retrieved = Presentation.RequestObjectRetrieved.requestObjectRetrieved(
                requested,
                Instant.ofEpochMilli(stored.requestObjectRetrievedAt),
            ).getOrThrow()
            Presentation.Submitted.submitted(
                retrieved,
                Instant.ofEpochMilli(stored.submittedAt),
                stored.walletResponse.toDomain(),
                stored.responseCode?.let { ResponseCode(it) },
            ).getOrThrow()
        }
        is PresentationStateRecord.TimedOut -> {
            val timedOutAt = Instant.ofEpochMilli(stored.timedOutAt)
            when {
                stored.submittedAt != null -> {
                    val retrieved = Presentation.RequestObjectRetrieved.requestObjectRetrieved(
                        requested,
                        Instant.ofEpochMilli(stored.requestObjectRetrievedAt ?: initiatedAt),
                    ).getOrThrow()
                    val submitted = Presentation.Submitted.submitted(
                        retrieved,
                        Instant.ofEpochMilli(stored.submittedAt),
                        WalletResponse.Error("timed_out", "Presentation timed out"),
                        null,
                    ).getOrThrow()
                    Presentation.TimedOut.timeOut(submitted, timedOutAt).getOrThrow()
                }
                stored.requestObjectRetrievedAt != null -> {
                    val retrieved = Presentation.RequestObjectRetrieved.requestObjectRetrieved(
                        requested,
                        Instant.ofEpochMilli(stored.requestObjectRetrievedAt),
                    ).getOrThrow()
                    Presentation.TimedOut.timeOut(retrieved, timedOutAt).getOrThrow()
                }
                else -> Presentation.TimedOut.timeOut(requested, timedOutAt).getOrThrow()
            }
        }
    }
}

@Serializable
private sealed class PresentationStateRecord {
    @Serializable
    @SerialName("requested")
    data object Requested : PresentationStateRecord()

    @Serializable
    @SerialName("request_object_retrieved")
    data class RequestObjectRetrieved(
        val requestObjectRetrievedAt: Long,
        val ephemeralEcPrivateKey: String?,
    ) : PresentationStateRecord()

    @Serializable
    @SerialName("submitted")
    data class Submitted(
        val requestObjectRetrievedAt: Long,
        val submittedAt: Long,
        val walletResponse: WalletResponseRecord,
        val responseCode: String?,
    ) : PresentationStateRecord()

    @Serializable
    @SerialName("timed_out")
    data class TimedOut(
        val requestObjectRetrievedAt: Long? = null,
        val submittedAt: Long? = null,
        val timedOutAt: Long,
    ) : PresentationStateRecord()
}

@Serializable
private sealed class WalletResponseMethodRecord {
    @Serializable
    @SerialName("poll")
    data object Poll : WalletResponseMethodRecord()

    @Serializable
    @SerialName("redirect")
    data class Redirect(val template: String) : WalletResponseMethodRecord()
}

private fun GetWalletResponseMethod.toRecord(): WalletResponseMethodRecord = when (this) {
    is GetWalletResponseMethod.Poll -> WalletResponseMethodRecord.Poll
    is GetWalletResponseMethod.Redirect -> WalletResponseMethodRecord.Redirect(redirectUriTemplate)
}

private fun WalletResponseMethodRecord.toDomain(): GetWalletResponseMethod = when (this) {
    is WalletResponseMethodRecord.Poll -> GetWalletResponseMethod.Poll
    is WalletResponseMethodRecord.Redirect -> GetWalletResponseMethod.Redirect(template)
}

@Serializable
private sealed class PresentationTypeRecord {
    @Serializable
    @SerialName("id_token")
    data class IdTokenRequest(val idTokenTypes: List<String>) : PresentationTypeRecord()

    @Serializable
    @SerialName("vp_token")
    data class VpTokenRequest(
        val presentationQuery: PresentationQueryRecord,
        val transactionData: List<JsonObject>? = null,
    ) : PresentationTypeRecord()

    @Serializable
    @SerialName("id_vp_token")
    data class IdAndVpToken(
        val idTokenTypes: List<String>,
        val presentationQuery: PresentationQueryRecord,
        val transactionData: List<JsonObject>? = null,
    ) : PresentationTypeRecord()
}

private fun PresentationType.toRecord(): PresentationTypeRecord = when (this) {
    is PresentationType.IdTokenRequest -> PresentationTypeRecord.IdTokenRequest(
        idTokenTypes = idTokenType.map { it.name },
    )
    is PresentationType.VpTokenRequest -> PresentationTypeRecord.VpTokenRequest(
        presentationQuery = presentationQuery.toRecord(),
        transactionData = transactionData?.map { it.value },
    )
    is PresentationType.IdAndVpToken -> PresentationTypeRecord.IdAndVpToken(
        idTokenTypes = idTokenType.map { it.name },
        presentationQuery = presentationQuery.toRecord(),
        transactionData = transactionData?.map { it.value },
    )
}

private fun PresentationTypeRecord.toDomain(): PresentationType {
    fun List<JsonObject>?.toTransactionData(): NonEmptyList<TransactionData>? =
        this?.mapNotNull { jsonObject ->
            val credentialIds = jsonObject["credential_ids"]?.jsonArray?.mapNotNull { element ->
                (element as? JsonPrimitive)?.contentOrNull
            } ?: emptyList()
            TransactionData.validate(jsonObject, credentialIds).getOrNull()
        }?.toNonEmptyListOrNull()

    return when (this) {
        is PresentationTypeRecord.IdTokenRequest -> PresentationType.IdTokenRequest(
            idTokenType = idTokenTypes.map { IdTokenType.valueOf(it) },
        )
        is PresentationTypeRecord.VpTokenRequest -> PresentationType.VpTokenRequest(
            presentationQuery = presentationQuery.toDomain(),
            transactionData = transactionData.toTransactionData(),
        )
        is PresentationTypeRecord.IdAndVpToken -> PresentationType.IdAndVpToken(
            idTokenType = idTokenTypes.map { IdTokenType.valueOf(it) },
            presentationQuery = presentationQuery.toDomain(),
            transactionData = transactionData.toTransactionData(),
        )
    }
}

@Serializable
private sealed class PresentationQueryRecord {
    @Serializable
    @SerialName("presentation_definition")
    data class PresentationDefinitionQuery(val presentationDefinition: String) : PresentationQueryRecord()

    @Serializable
    @SerialName("dcql")
    data class DcqlQuery(val dcql: JsonObject) : PresentationQueryRecord()
}

private fun PresentationQuery.toRecord(): PresentationQueryRecord = when (this) {
    is PresentationQuery.ByPresentationDefinition -> PresentationQueryRecord.PresentationDefinitionQuery(
        presentationDefinition = presentationDefinitionToJson(presentationDefinition),
    )
    is PresentationQuery.ByDigitalCredentialsQueryLanguage -> PresentationQueryRecord.DcqlQuery(
        dcql = jsonSupport.encodeToJsonElement(DCQL.serializer(), query).jsonObject,
    )
}

private fun PresentationQueryRecord.toDomain(): PresentationQuery = when (this) {
    is PresentationQueryRecord.PresentationDefinitionQuery -> PresentationQuery.ByPresentationDefinition(
        presentationDefinition = presentationDefinitionFromJson(presentationDefinition),
    )
    is PresentationQueryRecord.DcqlQuery -> PresentationQuery.ByDigitalCredentialsQueryLanguage(
        query = jsonSupport.decodeFromJsonElement(DCQL.serializer(), dcql),
    )
}

private fun presentationDefinitionToJson(presentationDefinition: PresentationDefinition): String {
    val jsonObject = PresentationDefinitionJackson.toJsonObject(presentationDefinition)
    return objectMapper.writeValueAsString(jsonObject)
}

private fun presentationDefinitionFromJson(payload: String): PresentationDefinition {
    val map = objectMapper.readValue<Map<String, Any?>>(payload)
    return PresentationDefinitionJackson.fromJsonObject(map).getOrThrow()
}

@Serializable
private sealed class WalletResponseRecord {
    @Serializable
    @SerialName("id_token")
    data class IdToken(val idToken: String) : WalletResponseRecord()

    @Serializable
    @SerialName("vp_token")
    data class VpToken(val vpContent: VpContentRecord) : WalletResponseRecord()

    @Serializable
    @SerialName("id_vp_token")
    data class IdAndVpToken(val idToken: String, val vpContent: VpContentRecord) : WalletResponseRecord()

    @Serializable
    @SerialName("error")
    data class Error(val error: String, val description: String?) : WalletResponseRecord()
}

private fun WalletResponse.toRecord(): WalletResponseRecord = when (this) {
    is WalletResponse.IdToken -> WalletResponseRecord.IdToken(idToken)
    is WalletResponse.VpToken -> WalletResponseRecord.VpToken(vpContent.toRecord())
    is WalletResponse.IdAndVpToken -> WalletResponseRecord.IdAndVpToken(idToken, vpContent.toRecord())
    is WalletResponse.Error -> WalletResponseRecord.Error(value, description)
}

private fun WalletResponseRecord.toDomain(): WalletResponse = when (this) {
    is WalletResponseRecord.IdToken -> WalletResponse.IdToken(idToken)
    is WalletResponseRecord.VpToken -> WalletResponse.VpToken(vpContent.toDomain())
    is WalletResponseRecord.IdAndVpToken -> WalletResponse.IdAndVpToken(idToken, vpContent.toDomain())
    is WalletResponseRecord.Error -> WalletResponse.Error(error, description)
}

@Serializable
private sealed class VpContentRecord {
    @Serializable
    @SerialName("presentation_exchange")
    data class PresentationExchange(
        val verifiablePresentations: List<VerifiablePresentationRecord>,
        val presentationSubmission: JsonObject,
    ) : VpContentRecord()

    @Serializable
    @SerialName("dcql")
    data class Dcql(
        val verifiablePresentations: Map<String, VerifiablePresentationRecord>,
    ) : VpContentRecord()
}

private fun VpContent.toRecord(): VpContentRecord = when (this) {
    is VpContent.PresentationExchange -> VpContentRecord.PresentationExchange(
        verifiablePresentations = verifiablePresentations.map { it.toRecord() },
        presentationSubmission = jsonSupport.encodeToJsonElement(PresentationSubmission.serializer(), presentationSubmission)
            .jsonObject,
    )
    is VpContent.DCQL -> VpContentRecord.Dcql(
        verifiablePresentations = verifiablePresentations.mapKeys { it.key.value }.mapValues { it.value.toRecord() },
    )
}

private fun VpContentRecord.toDomain(): VpContent = when (this) {
    is VpContentRecord.PresentationExchange -> {
        val presentations = verifiablePresentations.map { it.toDomain() }.toNonEmptyListOrNull()
            ?: throw IllegalStateException("vp_token must contain at least one presentation")
        val submission = jsonSupport.decodeFromJsonElement(PresentationSubmission.serializer(), presentationSubmission)
        VpContent.PresentationExchange(presentations, submission)
    }
    is VpContentRecord.Dcql -> {
        val presentations = verifiablePresentations.mapKeys { QueryId(it.key) }.mapValues { it.value.toDomain() }
        VpContent.DCQL(presentations)
    }
}

@Serializable
private data class VerifiablePresentationRecord(
    val format: String,
    val value: JsonElement,
)

private fun VerifiablePresentation.toRecord(): VerifiablePresentationRecord = when (this) {
    is VerifiablePresentation.Str -> VerifiablePresentationRecord(format.value, JsonPrimitive(value))
    is VerifiablePresentation.Json -> VerifiablePresentationRecord(format.value, value)
}

private fun VerifiablePresentationRecord.toDomain(): VerifiablePresentation {
    val format = Format(format)
    return when (value) {
        is JsonObject -> VerifiablePresentation.Json(value, format)
        is JsonPrimitive -> VerifiablePresentation.Str(value.content, format)
        else -> VerifiablePresentation.Json(value.jsonObject, format)
    }
}

@Serializable
private sealed class PresentationEventRecord {
    abstract val transactionId: String
    abstract val timestamp: Long

    @Serializable
    @SerialName("transaction_initialized")
    data class TransactionInitialized(
        override val transactionId: String,
        override val timestamp: Long,
        val response: JwtSecuredAuthorizationRequestTO,
    ) : PresentationEventRecord()

    @Serializable
    @SerialName("request_object_retrieved")
    data class RequestObjectRetrieved(
        override val transactionId: String,
        override val timestamp: Long,
        val jwt: String,
    ) : PresentationEventRecord()

    @Serializable
    @SerialName("failed_to_retrieve_request_object")
    data class FailedToRetrieveRequestObject(
        override val transactionId: String,
        override val timestamp: Long,
        val cause: String,
    ) : PresentationEventRecord()

    @Serializable
    @SerialName("presentation_definition_retrieved")
    data class PresentationDefinitionRetrieved(
        override val transactionId: String,
        override val timestamp: Long,
        val presentationDefinition: String,
    ) : PresentationEventRecord()

    @Serializable
    @SerialName("jarm_jwk_set_retrieved")
    data class JarmJwkSetRetrieved(
        override val transactionId: String,
        override val timestamp: Long,
        val jwkSet: JsonElement,
    ) : PresentationEventRecord()

    @Serializable
    @SerialName("failed_to_retrieve_jarm_jwk_set")
    data class FailedToRetrieveJarmJwkSet(
        override val transactionId: String,
        override val timestamp: Long,
        val cause: String,
    ) : PresentationEventRecord()

    @Serializable
    @SerialName("failed_to_retrieve_presentation_definition")
    data class FailedToRetrievePresentationDefinition(
        override val transactionId: String,
        override val timestamp: Long,
        val cause: String,
    ) : PresentationEventRecord()

    @Serializable
    @SerialName("wallet_response_posted")
    data class WalletResponsePosted(
        override val transactionId: String,
        override val timestamp: Long,
        val walletResponse: WalletResponseTO,
        val verifierEndpointResponse: WalletResponseAcceptedTO?,
    ) : PresentationEventRecord()

    @Serializable
    @SerialName("wallet_failed_to_post_response")
    data class WalletFailedToPostResponse(
        override val transactionId: String,
        override val timestamp: Long,
        val cause: WalletResponseValidationErrorRecord,
    ) : PresentationEventRecord()

    @Serializable
    @SerialName("verifier_got_wallet_response")
    data class VerifierGotWalletResponse(
        override val transactionId: String,
        override val timestamp: Long,
        val walletResponse: WalletResponseTO,
    ) : PresentationEventRecord()

    @Serializable
    @SerialName("verifier_failed_to_get_wallet_response")
    data class VerifierFailedToGetWalletResponse(
        override val transactionId: String,
        override val timestamp: Long,
        val cause: String,
    ) : PresentationEventRecord()

    @Serializable
    @SerialName("presentation_expired")
    data class PresentationExpired(
        override val transactionId: String,
        override val timestamp: Long,
    ) : PresentationEventRecord()
}

private fun PresentationEvent.toRecord(): PresentationEventRecord = when (this) {
    is PresentationEvent.TransactionInitialized -> PresentationEventRecord.TransactionInitialized(
        transactionId.value,
        timestamp.toEpochMilli(),
        response,
    )
    is PresentationEvent.RequestObjectRetrieved -> PresentationEventRecord.RequestObjectRetrieved(
        transactionId.value,
        timestamp.toEpochMilli(),
        jwt,
    )
    is PresentationEvent.FailedToRetrieveRequestObject -> PresentationEventRecord.FailedToRetrieveRequestObject(
        transactionId.value,
        timestamp.toEpochMilli(),
        cause,
    )
    is PresentationEvent.PresentationDefinitionRetrieved -> PresentationEventRecord.PresentationDefinitionRetrieved(
        transactionId.value,
        timestamp.toEpochMilli(),
        presentationDefinitionToJson(presentationDefinition),
    )
    is PresentationEvent.JarmJwkSetRetrieved -> PresentationEventRecord.JarmJwkSetRetrieved(
        transactionId.value,
        timestamp.toEpochMilli(),
        jwkSet,
    )
    is PresentationEvent.FailedToRetrieveJarmJwkSet -> PresentationEventRecord.FailedToRetrieveJarmJwkSet(
        transactionId.value,
        timestamp.toEpochMilli(),
        cause,
    )
    is PresentationEvent.FailedToRetrievePresentationDefinition -> PresentationEventRecord.FailedToRetrievePresentationDefinition(
        transactionId.value,
        timestamp.toEpochMilli(),
        cause,
    )
    is PresentationEvent.WalletResponsePosted -> PresentationEventRecord.WalletResponsePosted(
        transactionId.value,
        timestamp.toEpochMilli(),
        walletResponse,
        verifierEndpointResponse,
    )
    is PresentationEvent.WalletFailedToPostResponse -> PresentationEventRecord.WalletFailedToPostResponse(
        transactionId.value,
        timestamp.toEpochMilli(),
        cause.toRecord(),
    )
    is PresentationEvent.VerifierGotWalletResponse -> PresentationEventRecord.VerifierGotWalletResponse(
        transactionId.value,
        timestamp.toEpochMilli(),
        walletResponse,
    )
    is PresentationEvent.VerifierFailedToGetWalletResponse -> PresentationEventRecord.VerifierFailedToGetWalletResponse(
        transactionId.value,
        timestamp.toEpochMilli(),
        cause,
    )
    is PresentationEvent.PresentationExpired -> PresentationEventRecord.PresentationExpired(
        transactionId.value,
        timestamp.toEpochMilli(),
    )
}

private fun PresentationEventRecord.toDomain(): PresentationEvent = when (this) {
    is PresentationEventRecord.TransactionInitialized -> PresentationEvent.TransactionInitialized(
        TransactionId(transactionId),
        Instant.ofEpochMilli(timestamp),
        response,
    )
    is PresentationEventRecord.RequestObjectRetrieved -> PresentationEvent.RequestObjectRetrieved(
        TransactionId(transactionId),
        Instant.ofEpochMilli(timestamp),
        jwt,
    )
    is PresentationEventRecord.FailedToRetrieveRequestObject -> PresentationEvent.FailedToRetrieveRequestObject(
        TransactionId(transactionId),
        Instant.ofEpochMilli(timestamp),
        cause,
    )
    is PresentationEventRecord.PresentationDefinitionRetrieved -> PresentationEvent.PresentationDefinitionRetrieved(
        TransactionId(transactionId),
        Instant.ofEpochMilli(timestamp),
        presentationDefinitionFromJson(presentationDefinition),
    )
    is PresentationEventRecord.JarmJwkSetRetrieved -> PresentationEvent.JarmJwkSetRetrieved(
        TransactionId(transactionId),
        Instant.ofEpochMilli(timestamp),
        jwkSet,
    )
    is PresentationEventRecord.FailedToRetrieveJarmJwkSet -> PresentationEvent.FailedToRetrieveJarmJwkSet(
        TransactionId(transactionId),
        Instant.ofEpochMilli(timestamp),
        cause,
    )
    is PresentationEventRecord.FailedToRetrievePresentationDefinition -> PresentationEvent.FailedToRetrievePresentationDefinition(
        TransactionId(transactionId),
        Instant.ofEpochMilli(timestamp),
        cause,
    )
    is PresentationEventRecord.WalletResponsePosted -> PresentationEvent.WalletResponsePosted(
        TransactionId(transactionId),
        Instant.ofEpochMilli(timestamp),
        walletResponse,
        verifierEndpointResponse,
    )
    is PresentationEventRecord.WalletFailedToPostResponse -> PresentationEvent.WalletFailedToPostResponse(
        TransactionId(transactionId),
        Instant.ofEpochMilli(timestamp),
        cause.toDomain(),
    )
    is PresentationEventRecord.VerifierGotWalletResponse -> PresentationEvent.VerifierGotWalletResponse(
        TransactionId(transactionId),
        Instant.ofEpochMilli(timestamp),
        walletResponse,
    )
    is PresentationEventRecord.VerifierFailedToGetWalletResponse -> PresentationEvent.VerifierFailedToGetWalletResponse(
        TransactionId(transactionId),
        Instant.ofEpochMilli(timestamp),
        cause,
    )
    is PresentationEventRecord.PresentationExpired -> PresentationEvent.PresentationExpired(
        TransactionId(transactionId),
        Instant.ofEpochMilli(timestamp),
    )
}

@Serializable
private sealed class WalletResponseValidationErrorRecord {
    @Serializable
    @SerialName("missing_state")
    data object MissingState : WalletResponseValidationErrorRecord()

    @Serializable
    @SerialName("presentation_not_found")
    data object PresentationNotFound : WalletResponseValidationErrorRecord()

    @Serializable
    @SerialName("unexpected_response_mode")
    data class UnexpectedResponseMode(
        val requestId: String,
        val expected: String,
        val actual: String,
    ) : WalletResponseValidationErrorRecord()

    @Serializable
    @SerialName("presentation_not_in_expected_state")
    data object PresentationNotInExpectedState : WalletResponseValidationErrorRecord()

    @Serializable
    @SerialName("incorrect_state")
    data object IncorrectState : WalletResponseValidationErrorRecord()

    @Serializable
    @SerialName("missing_id_token")
    data object MissingIdToken : WalletResponseValidationErrorRecord()

    @Serializable
    @SerialName("invalid_vp_token")
    data object InvalidVpToken : WalletResponseValidationErrorRecord()

    @Serializable
    @SerialName("missing_vp_token")
    data object MissingVpToken : WalletResponseValidationErrorRecord()

    @Serializable
    @SerialName("missing_presentation_submission")
    data object MissingPresentationSubmission : WalletResponseValidationErrorRecord()

    @Serializable
    @SerialName("presentation_submission_must_not_be_present")
    data object PresentationSubmissionMustNotBePresent : WalletResponseValidationErrorRecord()

    @Serializable
    @SerialName("required_credential_set_not_satisfied")
    data object RequiredCredentialSetNotSatisfied : WalletResponseValidationErrorRecord()

    @Serializable
    @SerialName("invalid_presentation_submission")
    data object InvalidPresentationSubmission : WalletResponseValidationErrorRecord()

    @Serializable
    @SerialName("invalid_jarm")
    data class InvalidJarm(val message: String?) : WalletResponseValidationErrorRecord()
}

private fun WalletResponseValidationError.toRecord(): WalletResponseValidationErrorRecord = when (this) {
    WalletResponseValidationError.MissingState -> WalletResponseValidationErrorRecord.MissingState
    WalletResponseValidationError.PresentationNotFound -> WalletResponseValidationErrorRecord.PresentationNotFound
    is WalletResponseValidationError.UnexpectedResponseMode -> WalletResponseValidationErrorRecord.UnexpectedResponseMode(
        requestId = requestId.value,
        expected = expected.name,
        actual = actual.name,
    )
    WalletResponseValidationError.PresentationNotInExpectedState ->
        WalletResponseValidationErrorRecord.PresentationNotInExpectedState
    WalletResponseValidationError.IncorrectState -> WalletResponseValidationErrorRecord.IncorrectState
    WalletResponseValidationError.MissingIdToken -> WalletResponseValidationErrorRecord.MissingIdToken
    WalletResponseValidationError.InvalidVpToken -> WalletResponseValidationErrorRecord.InvalidVpToken
    WalletResponseValidationError.MissingVpToken -> WalletResponseValidationErrorRecord.MissingVpToken
    WalletResponseValidationError.MissingPresentationSubmission ->
        WalletResponseValidationErrorRecord.MissingPresentationSubmission
    WalletResponseValidationError.PresentationSubmissionMustNotBePresent ->
        WalletResponseValidationErrorRecord.PresentationSubmissionMustNotBePresent
    WalletResponseValidationError.RequiredCredentialSetNotSatisfied ->
        WalletResponseValidationErrorRecord.RequiredCredentialSetNotSatisfied
    WalletResponseValidationError.InvalidPresentationSubmission ->
        WalletResponseValidationErrorRecord.InvalidPresentationSubmission
    is WalletResponseValidationError.InvalidJarm -> WalletResponseValidationErrorRecord.InvalidJarm(error.message)
}

private fun WalletResponseValidationErrorRecord.toDomain(): WalletResponseValidationError = when (this) {
    WalletResponseValidationErrorRecord.MissingState -> WalletResponseValidationError.MissingState
    WalletResponseValidationErrorRecord.PresentationNotFound -> WalletResponseValidationError.PresentationNotFound
    is WalletResponseValidationErrorRecord.UnexpectedResponseMode ->
        WalletResponseValidationError.UnexpectedResponseMode(
            requestId = RequestId(requestId),
            expected = ResponseModeOption.valueOf(expected),
            actual = ResponseModeOption.valueOf(actual),
        )
    WalletResponseValidationErrorRecord.PresentationNotInExpectedState ->
        WalletResponseValidationError.PresentationNotInExpectedState
    WalletResponseValidationErrorRecord.IncorrectState -> WalletResponseValidationError.IncorrectState
    WalletResponseValidationErrorRecord.MissingIdToken -> WalletResponseValidationError.MissingIdToken
    WalletResponseValidationErrorRecord.InvalidVpToken -> WalletResponseValidationError.InvalidVpToken
    WalletResponseValidationErrorRecord.MissingVpToken -> WalletResponseValidationError.MissingVpToken
    WalletResponseValidationErrorRecord.MissingPresentationSubmission ->
        WalletResponseValidationError.MissingPresentationSubmission
    WalletResponseValidationErrorRecord.PresentationSubmissionMustNotBePresent ->
        WalletResponseValidationError.PresentationSubmissionMustNotBePresent
    WalletResponseValidationErrorRecord.RequiredCredentialSetNotSatisfied ->
        WalletResponseValidationError.RequiredCredentialSetNotSatisfied
    WalletResponseValidationErrorRecord.InvalidPresentationSubmission ->
        WalletResponseValidationError.InvalidPresentationSubmission
    is WalletResponseValidationErrorRecord.InvalidJarm ->
        WalletResponseValidationError.InvalidJarm(BadJOSEException(message ?: "Invalid JARM"))
}

private fun log(e: PresentationEvent) {
    fun txt(s: String) = "$s - tx: ${e.transactionId.value}"
    fun warn(s: String) = logger.warn(txt(s))
    fun info(s: String) = logger.info(txt(s))
    when (e) {
        is PresentationEvent.VerifierFailedToGetWalletResponse -> warn("Verifier failed to retrieve wallet response. Cause ${e.cause}")
        is PresentationEvent.FailedToRetrieveJarmJwkSet -> warn("Wallet failed to retrieve JARM JWKS. Cause ${e.cause}")
        is PresentationEvent.FailedToRetrievePresentationDefinition -> warn(
            "Wallet failed to retrieve presentation definition. Cause ${e.cause}",
        )
        is PresentationEvent.WalletFailedToPostResponse -> warn("Wallet failed to post response. Cause ${e.cause}")
        is PresentationEvent.FailedToRetrieveRequestObject -> warn("Wallet failed to retrieve request object. Cause ${e.cause}")
        is PresentationEvent.PresentationExpired -> info("Presentation expired")
        is PresentationEvent.JarmJwkSetRetrieved -> info("Wallet retrieved JARM JWKS")
        is PresentationEvent.PresentationDefinitionRetrieved -> info("Wallet retrieved presentation definition")
        is PresentationEvent.RequestObjectRetrieved -> info("Wallet retrieved Request Object")
        is PresentationEvent.TransactionInitialized -> info("Verifier initialized transaction")
        is PresentationEvent.VerifierGotWalletResponse -> info("Verifier retrieved wallet response")
        is PresentationEvent.WalletResponsePosted -> info("Wallet posted response")
    }
}
