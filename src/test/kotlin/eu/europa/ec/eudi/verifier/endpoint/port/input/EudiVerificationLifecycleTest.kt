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
package eu.europa.ec.eudi.verifier.endpoint.port.input

import arrow.core.Either
import eu.europa.ec.eudi.verifier.endpoint.TestContext
import eu.europa.ec.eudi.verifier.endpoint.adapter.input.web.VerifierApiClient
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.persistence.PresentationInMemoryRepo
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.utils.getOrThrow
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.CreateQueryWalletResponseRedirectUri
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.GenerateResponseCode
import eu.europa.ec.eudi.verifier.endpoint.port.out.jose.VerifyEncryptedResponse
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.presentation.ValidateVerifiablePresentation
import io.ktor.client.HttpClient
import kotlinx.coroutines.test.runTest
import kotlinx.datetime.TimeZone
import java.net.URL
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

class EudiVerificationLifecycleTest {

    @Test
    fun `request object fetch after verifier max age is rejected and marks presentation timed out`() = runTest {
        val repo = PresentationInMemoryRepo()
        val clock = MutableClock(TestContext.testClock.now() + 16.minutes)
        val requested = requestedPresentation()
        repo.storePresentation(requested)

        val useCase = RetrieveRequestObjectLive(
            loadPresentationByRequestId = repo.loadPresentationByRequestId,
            storePresentation = repo.storePresentation,
            createJar = TestContext.createJar,
            verifierConfig = verifierConfig(),
            clock = clock,
            publishPresentationEvent = repo.publishPresentationEvent,
            httpClient = HttpClient(),
        )

        val result = useCase(requested.requestId, RetrieveRequestObjectMethod.Get)

        assertEquals(Either.Left(RetrieveRequestObjectError.PresentationNotFound), result)
        val stored = repo.loadPresentationById(requested.id)
        assertIs<Presentation.TimedOut>(stored)
        assertEquals(clock.now(), stored.timedOutAt)
        assertExpiredEvent(repo, requested.id)
    }

    @Test
    fun `request object fetch crossing verifier max age before store is rejected and marks presentation timed out`() = runTest {
        val repo = PresentationInMemoryRepo()
        val requested = requestedPresentation()
        val clock = MutableClock(requested.initiatedAt + 15.minutes - 1.seconds)
        repo.storePresentation(requested)

        val useCase = RetrieveRequestObjectLive(
            loadPresentationByRequestId = repo.loadPresentationByRequestId,
            storePresentation = repo.storePresentation,
            createJar = { _, _, _, _, _ ->
                clock.advanceTo(requested.initiatedAt + 15.minutes + 1.seconds)
                Either.Right("request.jwt")
            },
            verifierConfig = verifierConfig(),
            clock = clock,
            publishPresentationEvent = repo.publishPresentationEvent,
            httpClient = HttpClient(),
        )

        val result = useCase(requested.requestId, RetrieveRequestObjectMethod.Get)

        assertEquals(Either.Left(RetrieveRequestObjectError.PresentationNotFound), result)
        val stored = repo.loadPresentationById(requested.id)
        assertIs<Presentation.TimedOut>(stored)
        assertEquals(clock.now(), stored.timedOutAt)
        assertExpiredEvent(repo, requested.id)
    }

    @Test
    fun `wallet response after verifier max age is rejected and marks presentation timed out`() = runTest {
        val repo = PresentationInMemoryRepo()
        val requested = requestedPresentation()
        val retrievedClock = MutableClock(TestContext.testClock.now())
        val retrieved = requested.retrieveRequestObject(retrievedClock).getOrThrow()
        repo.storePresentation(retrieved)

        val expiredClock = MutableClock(TestContext.testClock.now() + 16.minutes)
        val useCase = PostWalletResponseLive(
            loadPresentationByRequestId = repo.loadPresentationByRequestId,
            storePresentation = repo.storePresentation,
            verifyEncryptedResponse = VerifyEncryptedResponse { _, _, _ -> error("expired response must not be decrypted") },
            clock = expiredClock,
            verifierConfig = verifierConfig(),
            generateResponseCode = GenerateResponseCode.fixed(ResponseCode("response-code")),
            createQueryWalletResponseRedirectUri = CreateQueryWalletResponseRedirectUri.simple("https"),
            publishPresentationEvent = repo.publishPresentationEvent,
            validateVerifiablePresentation = ValidateVerifiablePresentation.NoOp,
        )

        val result = useCase(
            requested.requestId,
            AuthorisationResponse.DirectPost(
                AuthorisationResponseTO(
                    state = requested.requestId.value,
                    error = "expired",
                    errorDescription = null,
                ),
            ),
        )

        assertEquals(Either.Left(WalletResponseValidationError.PresentationNotFound), result)
        val stored = repo.loadPresentationById(requested.id)
        assertIs<Presentation.TimedOut>(stored)
        assertEquals(expiredClock.now(), stored.timedOutAt)
        assertExpiredEvent(repo, requested.id)
    }

    @Test
    fun `wallet response crossing verifier max age before store is rejected and marks presentation timed out`() = runTest {
        val repo = PresentationInMemoryRepo()
        val requested = requestedPresentation(
            getWalletResponseMethod = GetWalletResponseMethod.Redirect(
                "https://client.example/callback?response_code=${CreateQueryWalletResponseRedirectUri.RESPONSE_CODE_PLACE_HOLDER}",
            ),
        )
        val retrievedClock = MutableClock(TestContext.testClock.now())
        val retrieved = requested.retrieveRequestObject(retrievedClock).getOrThrow()
        repo.storePresentation(retrieved)

        val responseClock = MutableClock(retrieved.requestObjectRetrievedAt + 15.minutes - 1.seconds)
        val useCase = PostWalletResponseLive(
            loadPresentationByRequestId = repo.loadPresentationByRequestId,
            storePresentation = repo.storePresentation,
            verifyEncryptedResponse = VerifyEncryptedResponse { _, _, _ -> error("direct_post response must not be decrypted") },
            clock = responseClock,
            verifierConfig = verifierConfig(),
            generateResponseCode = GenerateResponseCode {
                responseClock.advanceTo(retrieved.requestObjectRetrievedAt + 15.minutes + 1.seconds)
                ResponseCode("response-code")
            },
            createQueryWalletResponseRedirectUri = CreateQueryWalletResponseRedirectUri.simple("https"),
            publishPresentationEvent = repo.publishPresentationEvent,
            validateVerifiablePresentation = ValidateVerifiablePresentation.NoOp,
        )

        val result = useCase(
            requested.requestId,
            AuthorisationResponse.DirectPost(
                AuthorisationResponseTO(
                    state = requested.requestId.value,
                    error = "access_denied",
                    errorDescription = null,
                ),
            ),
        )

        assertEquals(Either.Left(WalletResponseValidationError.PresentationNotFound), result)
        val stored = repo.loadPresentationById(requested.id)
        assertIs<Presentation.TimedOut>(stored)
        assertEquals(responseClock.now(), stored.timedOutAt)
        assertExpiredEvent(repo, requested.id)
    }

    @Test
    fun `wallet response after original verifier deadline is rejected even when request object was fetched late`() = runTest {
        val repo = PresentationInMemoryRepo()
        val requested = requestedPresentation()
        val retrievedClock = MutableClock(requested.initiatedAt + 14.minutes)
        val retrieved = requested.retrieveRequestObject(retrievedClock).getOrThrow()
        repo.storePresentation(retrieved)

        val responseClock = MutableClock(requested.initiatedAt + 16.minutes)
        val useCase = PostWalletResponseLive(
            loadPresentationByRequestId = repo.loadPresentationByRequestId,
            storePresentation = repo.storePresentation,
            verifyEncryptedResponse = VerifyEncryptedResponse { _, _, _ -> error("expired response must not be decrypted") },
            clock = responseClock,
            verifierConfig = verifierConfig(),
            generateResponseCode = GenerateResponseCode.fixed(ResponseCode("response-code")),
            createQueryWalletResponseRedirectUri = CreateQueryWalletResponseRedirectUri.simple("https"),
            publishPresentationEvent = repo.publishPresentationEvent,
            validateVerifiablePresentation = ValidateVerifiablePresentation.NoOp,
        )

        val result = useCase(
            requested.requestId,
            AuthorisationResponse.DirectPost(
                AuthorisationResponseTO(
                    state = requested.requestId.value,
                    error = "access_denied",
                    errorDescription = null,
                ),
            ),
        )

        assertEquals(Either.Left(WalletResponseValidationError.PresentationNotFound), result)
        val stored = repo.loadPresentationById(requested.id)
        assertIs<Presentation.TimedOut>(stored)
        assertEquals(responseClock.now(), stored.timedOutAt)
        assertExpiredEvent(repo, requested.id)
    }

    private suspend fun assertExpiredEvent(repo: PresentationInMemoryRepo, transactionId: TransactionId) {
        val events = assertNotNull(repo.loadPresentationEvents(transactionId))
        assertIs<PresentationEvent.PresentationExpired>(events.last())
    }

    private fun requestedPresentation(
        getWalletResponseMethod: GetWalletResponseMethod = GetWalletResponseMethod.Poll,
    ): Presentation.Requested {
        val dcql = VerifierApiClient.loadInitTransactionTO("fixtures/eudi/00-dcql.json").dcqlQuery!!
        return Presentation.Requested(
            id = TransactionId("tx-${System.nanoTime()}"),
            initiatedAt = TestContext.testClock.now(),
            query = dcql,
            transactionData = null,
            requestId = RequestId("req-${System.nanoTime()}"),
            requestUriMethod = RequestUriMethod.Get,
            nonce = Nonce("nonce-${System.nanoTime()}"),
            responseMode = ResponseMode.DirectPost,
            getWalletResponseMethod = getWalletResponseMethod,
            issuerChain = null,
            profile = Profile.OpenId4VP,
        )
    }

    private fun verifierConfig(): VerifierConfig =
        VerifierConfig(
            verifierId = TestContext.verifierId,
            requestJarOption = EmbedOption.ByReference { _ -> URL("https://verifier.example/request.jwt") },
            requestUriMethod = RequestUriMethod.Get,
            responseModeOption = ResponseModeOption.DirectPost,
            responseUriBuilder = { _ -> URL("https://verifier.example/response") },
            maxAge = 15.minutes,
            clientMetaData = TestContext.clientMetaData,
            transactionDataHashAlgorithm = HashAlgorithm.SHA_256,
            authorizationRequestUri = UnresolvedAuthorizationRequestUri.fromUri("eudi-openid4vp://").getOrThrow(),
            trustSourcesConfig = emptyMap(),
            issuerMetadataAllowedIssuerPatterns = emptySet(),
        )

    private class MutableClock(private var current: kotlin.time.Instant) : Clock {
        override fun now(): kotlin.time.Instant = current
        override fun timeZone(): TimeZone = TimeZone.UTC

        fun advanceTo(now: kotlin.time.Instant) {
            current = now
        }
    }
}
