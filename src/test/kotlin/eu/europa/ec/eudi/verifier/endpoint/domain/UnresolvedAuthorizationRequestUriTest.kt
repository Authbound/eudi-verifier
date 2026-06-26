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
package eu.europa.ec.eudi.verifier.endpoint.domain

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class UnresolvedAuthorizationRequestUriTest {

    @Test
    fun `rejects browser executable and local file schemes`() {
        val disallowedSchemes = listOf("javascript", "data", "file", "blob", "about", "vbscript")

        for (scheme in disallowedSchemes) {
            assertFalse(UnresolvedAuthorizationRequestUri.fromScheme(scheme).isSuccess)
            assertFalse(UnresolvedAuthorizationRequestUri.fromUri("$scheme:payload").isSuccess)
        }
    }

    @Test
    fun `rejects relative authorization request uris`() {
        assertFalse(UnresolvedAuthorizationRequestUri.fromUri("wallet/request").isSuccess)
    }

    @Test
    fun `accepts wallet and universal link schemes`() {
        UnresolvedAuthorizationRequestUri.fromScheme("haip-vp").also { result ->
            assertTrue(result.isSuccess, result.exceptionOrNull()?.message.orEmpty())
        }
        UnresolvedAuthorizationRequestUri.fromScheme("eudi-openid4vp").also { result ->
            assertTrue(result.isSuccess, result.exceptionOrNull()?.message.orEmpty())
        }
        UnresolvedAuthorizationRequestUri.fromUri("https://wallet.example/authorize").also { result ->
            assertTrue(result.isSuccess, result.exceptionOrNull()?.message.orEmpty())
        }
    }
}
