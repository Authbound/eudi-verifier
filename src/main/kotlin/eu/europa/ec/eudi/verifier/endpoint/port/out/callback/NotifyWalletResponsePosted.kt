package eu.europa.ec.eudi.verifier.endpoint.port.out.callback

import eu.europa.ec.eudi.verifier.endpoint.domain.TransactionId
import eu.europa.ec.eudi.verifier.endpoint.port.input.WalletResponseTO
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.slf4j.LoggerFactory
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.client.WebClient

fun interface NotifyWalletResponsePosted {
    suspend operator fun invoke(transactionId: TransactionId, walletResponse: WalletResponseTO)

    companion object {
        val Noop = NotifyWalletResponsePosted { _, _ -> }
    }
}

class BackendWalletResponsePostedNotifier(
    backendBaseUrl: String,
    private val internalToken: String,
    private val webClient: WebClient = WebClient.builder().build(),
) : NotifyWalletResponsePosted {

    private val callbackUrl = "${backendBaseUrl.removeSuffix("/")}/internal/eudi-verifier/presentations/wallet-response"

    override suspend fun invoke(transactionId: TransactionId, walletResponse: WalletResponseTO) {
        val payload = Json.encodeToString(
            BackendWalletResponsePostedRequest(
                transactionId = transactionId.value,
                walletResponse = walletResponse,
            ),
        )

        webClient.post()
            .uri(callbackUrl)
            .contentType(MediaType.APPLICATION_JSON)
            .header("X-Request-Type", "internal-service")
            .header("X-Internal-Token", internalToken)
            .bodyValue(payload)
            .retrieve()
            .toBodilessEntity()
            .block()
    }

    companion object {
        private val logger = LoggerFactory.getLogger(BackendWalletResponsePostedNotifier::class.java)

        fun fromConfigOrNoop(
            backendBaseUrl: String?,
            internalToken: String?,
        ): NotifyWalletResponsePosted {
            val normalizedUrl = backendBaseUrl?.trim().orEmpty()
            val normalizedToken = internalToken?.trim().orEmpty()

            if (normalizedUrl.isBlank() || normalizedToken.isBlank()) {
                logger.info("Authbound backend wallet-response callback disabled")
                return NotifyWalletResponsePosted.Noop
            }

            logger.info("Authbound backend wallet-response callback enabled: {}", normalizedUrl)
            return BackendWalletResponsePostedNotifier(normalizedUrl, normalizedToken)
        }
    }
}

@Serializable
private data class BackendWalletResponsePostedRequest(
    val transactionId: String,
    val walletResponse: WalletResponseTO,
)
