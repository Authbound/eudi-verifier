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
import eu.europa.ec.eudi.verifier.endpoint.TestContext
import eu.europa.ec.eudi.verifier.endpoint.adapter.input.web.VerifierApiClient
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.utils.getOrThrow
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import kotlinx.coroutines.test.runTest
import kotlinx.datetime.LocalDateTime
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toInstant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant

class PresentationInMemoryRepoTest {

    @Test
    fun `loadIncompletePresentationsOlderThan excludes submitted presentations`() = runTest {
        val repo = PresentationInMemoryRepo()
        val requested = requestedPresentation("submitted-sweep")
        val requestObjectRetrieved = requested.retrieveRequestObject(clockAt(seconds = 1)).getOrThrow()
        val submitted = requestObjectRetrieved.submit(clockAt(seconds = 2), WalletResponse.Error("error", null), null).getOrThrow()

        repo.storePresentation(requested)
        repo.storePresentation(submitted)

        val incomplete = repo.loadIncompletePresentationsOlderThan(at = instantAt(seconds = 3))

        assertTrue(incomplete.isEmpty())
    }

    @Test
    fun `storePresentation keeps submitted presentation when timeout update arrives later`() = runTest {
        val repo = PresentationInMemoryRepo()
        val requested = requestedPresentation("submitted-wins")
        val requestObjectRetrieved = requested.retrieveRequestObject(clockAt(seconds = 1)).getOrThrow()
        val submitted = requestObjectRetrieved.submit(clockAt(seconds = 2), WalletResponse.Error("error", null), null).getOrThrow()
        val timedOut = submitted.timedOut(clockAt(seconds = 3)).getOrThrow()

        repo.storePresentation(requested)
        repo.storePresentation(submitted)
        repo.storePresentation(timedOut)

        val loaded = repo.loadPresentationById(requested.id)

        assertIs<Presentation.Submitted>(loaded)
        assertEquals(submitted.submittedAt, loaded.submittedAt)
        assertEquals(submitted.requestId, loaded.requestId)
    }

    @Test
    fun `storePresentation keeps timed out presentation when wallet response wins race too late`() = runTest {
        val repo = PresentationInMemoryRepo()
        val requested = requestedPresentation("timeout-wins")
        val requestObjectRetrieved = requested.retrieveRequestObject(clockAt(seconds = 1)).getOrThrow()
        val timedOut = requestObjectRetrieved.timedOut(clockAt(seconds = 2)).getOrThrow()
        val submitted = requestObjectRetrieved.submit(clockAt(seconds = 3), WalletResponse.Error("error", null), null).getOrThrow()

        repo.storePresentation(requested)
        repo.storePresentation(timedOut)
        repo.storePresentation(submitted)

        val loaded = repo.loadPresentationById(requested.id)

        assertIs<Presentation.TimedOut>(loaded)
        assertEquals(timedOut.timedOutAt, loaded.timedOutAt)
        assertEquals(timedOut.requestObjectRetrievedAt, loaded.requestObjectRetrievedAt)
    }

    private fun requestedPresentation(suffix: String): Presentation.Requested {
        val dcql = VerifierApiClient.loadInitTransactionTO("fixtures/eudi/00-dcql.json").dcqlQuery!!
        val jwk = ECKeyGenerator(Curve.P_256)
            .keyUse(KeyUse.ENCRYPTION)
            .generate()
        return Presentation.Requested(
            id = TransactionId("tx-$suffix"),
            initiatedAt = BASE_TIME,
            query = dcql,
            transactionData = null,
            requestId = RequestId("req-$suffix"),
            requestUriMethod = RequestUriMethod.Get,
            nonce = Nonce("nonce-$suffix"),
            responseMode = ResponseMode.DirectPostJwt(jwk),
            getWalletResponseMethod = GetWalletResponseMethod.Poll,
            issuerChain = null,
            profile = Profile.OpenId4VP,
        )
    }

    private fun clockAt(seconds: Int): Clock = Clock.fixed(instantAt(seconds), TimeZone.UTC)

    private fun instantAt(seconds: Int): Instant = BASE_TIME + seconds.seconds

    private companion object {
        val BASE_TIME: Instant = LocalDateTime(1974, 11, 2, 10, 5, 33).toInstant(TimeZone.UTC)
    }
}
