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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.authbound

import eu.europa.ec.eudi.verifier.endpoint.port.input.WalletResponseTO
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PublishPresentationEvent
import io.ktor.client.HttpClient
import io.ktor.client.plugins.ClientRequestException
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.contentType
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.slf4j.Logger
import org.slf4j.LoggerFactory

@Serializable
data class AuthboundWalletResponseCallbackTO(
    @SerialName("transaction_id") val transactionId: String,
    @SerialName("wallet_response") val walletResponse: WalletResponseTO,
)

/**
 * Wraps an existing [PublishPresentationEvent] and notifies the Authbound backend
 * when a wallet response has been submitted.
 *
 * This is best-effort: callback failures must not break the verifier flow.
 */
class AuthboundBackendCallbackPublisher(
    private val delegate: PublishPresentationEvent,
    private val httpClient: HttpClient,
    private val backendBaseUrl: String,
    private val internalToken: String,
) : PublishPresentationEvent {

    private val logger: Logger = LoggerFactory.getLogger(AuthboundBackendCallbackPublisher::class.java)

    override suspend fun invoke(event: PresentationEvent) {
        delegate(event)

        if (event is PresentationEvent.WalletResponsePosted) {
            notifyBackend(event)
        }
    }

    private suspend fun notifyBackend(event: PresentationEvent.WalletResponsePosted) {
        val url = backendBaseUrl.trimEnd('/') + "/internal/eudi-verifier/presentations/wallet-response"
        val payload = AuthboundWalletResponseCallbackTO(
            transactionId = event.transactionId.value,
            walletResponse = event.walletResponse,
        )

        try {
            httpClient.post(url) {
                contentType(ContentType.Application.Json)
                header("X-Request-Type", "internal-service")
                header("X-Internal-Token", internalToken)
                setBody(payload)
            }
            logger.info("Notified Authbound backend for tx={}", event.transactionId.value)
        } catch (e: ClientRequestException) {
            val status = e.response.status.value
            logger.warn("Authbound backend callback failed for tx={} status={}", event.transactionId.value, status, e)
        } catch (t: Throwable) {
            logger.warn("Authbound backend callback failed for tx={}", event.transactionId.value, t)
        }
    }
}
