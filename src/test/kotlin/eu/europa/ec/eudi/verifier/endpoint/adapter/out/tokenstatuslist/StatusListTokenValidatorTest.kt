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

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.sdjwt.SdJwt
import eu.europa.ec.eudi.sdjwt.SdJwtAndKbJwt
import eu.europa.ec.eudi.sdjwt.vc.SdJwtVcSpec
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.ProvideTrustSource
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.X5CShouldBe
import eu.europa.ec.eudi.verifier.endpoint.domain.Clock
import eu.europa.ec.eudi.verifier.endpoint.domain.TransactionId
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PublishPresentationEvent
import io.ktor.client.HttpClient
import io.ktor.client.engine.apache.Apache
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.fail
import org.junit.jupiter.api.Test

class StatusListTokenValidatorTest {

    @Test
    fun `missing status list reference fails validation`() = runTest {
        val jwt = SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.ES256).build(),
            JWTClaimsSet.Builder()
                .claim(SdJwtVcSpec.VCT, "urn:example:vct")
                .build(),
        )
        val sdJwtAndKbJwt = SdJwtAndKbJwt(SdJwt(jwt, emptyList()), jwt)

        val validator = StatusListTokenValidator(
            httpClient = HttpClient(Apache),
            clock = Clock.System,
            publishPresentationEvent = PublishPresentationEvent { },
            provideTrustSource = ProvideTrustSource.forAll(X5CShouldBe.Ignored),
            cache = NoopStatusListTokenCache,
        )

        val error = try {
            validator.validate(sdJwtAndKbJwt, TransactionId("tx"))
            fail("Expected StatusCheckException")
        } catch (error: StatusCheckException) {
            error
        }

        assertEquals("Missing status_list reference in SD-JWT VC", error.reason)
    }
}
