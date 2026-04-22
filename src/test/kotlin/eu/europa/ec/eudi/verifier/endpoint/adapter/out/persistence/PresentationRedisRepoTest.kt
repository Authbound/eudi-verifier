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

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import eu.europa.ec.eudi.verifier.endpoint.RedisTestContainer
import eu.europa.ec.eudi.verifier.endpoint.TestContext
import eu.europa.ec.eudi.verifier.endpoint.adapter.input.web.VerifierApiClient
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.utils.getOrThrow
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.port.input.InitTransactionResponse
import eu.europa.ec.eudi.verifier.endpoint.port.input.ProfileTO
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.StorePresentationResult
import kotlinx.coroutines.reactor.awaitSingleOrNull
import kotlinx.coroutines.test.runTest
import kotlinx.datetime.TimeZone
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.data.redis.connection.RedisStandaloneConfiguration
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory
import org.springframework.data.redis.core.ReactiveStringRedisTemplate
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

class PresentationRedisRepoTest {
    private lateinit var connectionFactory: LettuceConnectionFactory
    private lateinit var redis: ReactiveStringRedisTemplate
    private lateinit var repo: PresentationRedisRepo

    @BeforeEach
    fun setup() {
        assumeTrue(RedisTestContainer.isDockerAvailable(), "Docker is required for Redis integration tests")
        RedisTestContainer.startIfNeeded()
        val config = RedisStandaloneConfiguration(RedisTestContainer.host, RedisTestContainer.port)
        connectionFactory = LettuceConnectionFactory(config)
        connectionFactory.afterPropertiesSet()
        redis = ReactiveStringRedisTemplate(connectionFactory)
        repo = PresentationRedisRepo(redis, TestContext.testClock, 5.seconds)
        flushRedis()
    }

    @AfterEach
    fun tearDown() {
        if (this::connectionFactory.isInitialized) {
            connectionFactory.destroy()
        }
    }

    @Test
    fun `stores and loads presentation by id and request id`() = runTest {
        val presentation = requestedPresentation()
        assertEquals(StorePresentationResult.Stored, repo.storePresentation(presentation))

        val loaded = repo.loadPresentationById(presentation.id)
        assertNotNull(loaded)
        assertIs<Presentation.Requested>(loaded)
        assertEquals(presentation.requestId, loaded.requestId)
        assertEquals(presentation.nonce, loaded.nonce)
        assertEquals(presentation.requestUriMethod, loaded.requestUriMethod)
        assertEquals(presentation.responseMode.option, loaded.responseMode.option)
        val loadedResponseMode = loaded.responseMode as ResponseMode.DirectPostJwt
        val originalResponseMode = presentation.responseMode as ResponseMode.DirectPostJwt
        assertEquals(
            originalResponseMode.ephemeralResponseEncryptionKey.toJSONString(),
            loadedResponseMode.ephemeralResponseEncryptionKey.toJSONString(),
        )

        val loadedByRequest = repo.loadPresentationByRequestId(presentation.requestId)
        assertNotNull(loadedByRequest)
        assertIs<Presentation.Requested>(loadedByRequest)
        assertEquals(presentation.id, loadedByRequest.id)
    }

    @Test
    fun `publishes and loads presentation events`() = runTest {
        val presentation = requestedPresentation()
        repo.storePresentation(presentation)
        val transactionId = presentation.id
        val event = PresentationEvent.TransactionInitialized(
            transactionId = transactionId,
            timestamp = TestContext.testClock.now(),
            response = InitTransactionResponse.JwtSecuredAuthorizationRequestTO.byValue(
                transactionId = transactionId.value,
                clientId = "Verifier",
                request = "request.jwt",
                authorizationRequestUri = java.net.URI("haip-vp://wallet"),
            ),
            profile = ProfileTO.OpenId4VP,
        )

        repo.publishPresentationEvent(event)

        val events = repo.loadPresentationEvents(transactionId)
        assertNotNull(events)
        assertEquals(1, events.size)
        assertIs<PresentationEvent.TransactionInitialized>(events.head)
    }

    @Test
    fun `expires presentation after ttl`() = runTest {
        val shortRepo = PresentationRedisRepo(redis, TestContext.testClock, 150.milliseconds)
        val presentation = requestedPresentation()
        shortRepo.storePresentation(presentation)
        Thread.sleep(300)
        val loaded = shortRepo.loadPresentationById(presentation.id)
        assertEquals(null, loaded)
    }

    fun `loadIncompletePresentationsOlderThan excludes submitted presentations`() = runTest {
        val requested = requestedPresentation()
        val requestObjectRetrieved = requested.retrieveRequestObject(clockAt(seconds = 1)).getOrThrow()
        val submitted = requestObjectRetrieved.submit(clockAt(seconds = 2), WalletResponse.Error("error", null), null).getOrThrow()

        repo.storePresentation(requested)
        repo.storePresentation(submitted)

        val incomplete = repo.loadIncompletePresentationsOlderThan(at = instantAt(seconds = 3))

        assertTrue(incomplete.isEmpty())
    }

    @Test
    fun `storePresentation keeps submitted presentation when timeout update arrives later`() = runTest {
        val requested = requestedPresentation()
        val requestObjectRetrieved = requested.retrieveRequestObject(clockAt(seconds = 1)).getOrThrow()
        val submitted = requestObjectRetrieved.submit(clockAt(seconds = 2), WalletResponse.Error("error", null), null).getOrThrow()
        val timedOut = submitted.timedOut(clockAt(seconds = 3)).getOrThrow()

        assertEquals(StorePresentationResult.Stored, repo.storePresentation(requested))
        assertEquals(StorePresentationResult.Stored, repo.storePresentation(submitted))
        assertEquals(StorePresentationResult.SkippedTerminal, repo.storePresentation(timedOut))

        val loaded = repo.loadPresentationById(requested.id)

        assertIs<Presentation.Submitted>(loaded)
        assertEquals(submitted.submittedAt, loaded.submittedAt)
        assertEquals(submitted.requestId, loaded.requestId)
    }

    @Test
    fun `storePresentation keeps timed out presentation when wallet response wins race too late`() = runTest {
        val requested = requestedPresentation()
        val requestObjectRetrieved = requested.retrieveRequestObject(clockAt(seconds = 1)).getOrThrow()
        val timedOut = requestObjectRetrieved.timedOut(clockAt(seconds = 2)).getOrThrow()
        val submitted = requestObjectRetrieved.submit(clockAt(seconds = 3), WalletResponse.Error("error", null), null).getOrThrow()

        assertEquals(StorePresentationResult.Stored, repo.storePresentation(requested))
        assertEquals(StorePresentationResult.Stored, repo.storePresentation(timedOut))
        assertEquals(StorePresentationResult.SkippedTerminal, repo.storePresentation(submitted))

        val loaded = repo.loadPresentationById(requested.id)

        assertIs<Presentation.TimedOut>(loaded)
        assertEquals(timedOut.timedOutAt, loaded.timedOutAt)
        assertEquals(timedOut.requestObjectRetrievedAt, loaded.requestObjectRetrievedAt)
    }

    @Test
    fun `claims expired incomplete presentations once`() = runTest {
        val presentation = requestedPresentation()
        repo.storePresentation(presentation)

        val firstLoad = repo.loadIncompletePresentationsOlderThan(TestContext.testClock.now())
        val secondLoad = repo.loadIncompletePresentationsOlderThan(TestContext.testClock.now())

        assertEquals(listOf(presentation.id), firstLoad.map { it.id })
        assertEquals(emptyList(), secondLoad.map { it.id })
    }

    @Test
    fun `indexes retrieved presentations by original verifier deadline`() = runTest {
        val requested = requestedPresentation()
        val retrieved = requested.retrieveRequestObject(
            Clock.fixed(TestContext.testClock.now() + 14.seconds, TimeZone.UTC),
        ).getOrThrow()
        repo.storePresentation(retrieved)

        val loaded = repo.loadIncompletePresentationsOlderThan(TestContext.testClock.now() + 1.seconds)

        assertEquals(listOf(retrieved.id), loaded.map { it.id })
    }

    private fun requestedPresentation(): Presentation.Requested {
        val dcql = VerifierApiClient.loadInitTransactionTO("fixtures/eudi/00-dcql.json").dcqlQuery!!
        val jwk = ECKeyGenerator(Curve.P_256)
            .keyUse(KeyUse.ENCRYPTION)
            .generate()
        return Presentation.Requested(
            id = TransactionId("tx-${System.nanoTime()}"),
            initiatedAt = BASE_TIME,
            query = dcql,
            transactionData = null,
            requestId = RequestId("req-${System.nanoTime()}"),
            requestUriMethod = RequestUriMethod.Get,
            nonce = Nonce("nonce-${System.nanoTime()}"),
            responseMode = ResponseMode.DirectPostJwt(jwk),
            getWalletResponseMethod = GetWalletResponseMethod.Poll,
            issuerChain = null,
            profile = Profile.OpenId4VP,
        )
    }

    private fun clockAt(seconds: Int): Clock = Clock.fixed(instantAt(seconds), kotlinx.datetime.TimeZone.UTC)

    private fun instantAt(seconds: Int) = BASE_TIME + seconds.seconds

    private fun flushRedis() = runTest {
        redis.connectionFactory.reactiveConnection.serverCommands().flushAll().awaitSingleOrNull()
    }

    private companion object {
        val BASE_TIME = TestContext.testClock.now()
    }
}
