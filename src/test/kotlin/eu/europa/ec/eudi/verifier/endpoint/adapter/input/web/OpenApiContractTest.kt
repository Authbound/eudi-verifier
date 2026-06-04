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
package eu.europa.ec.eudi.verifier.endpoint.adapter.input.web

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import org.springframework.core.io.DefaultResourceLoader
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class OpenApiContractTest {

    private val openApi = DefaultResourceLoader()
        .getResource("classpath:public/openapi.json")
        .inputStream
        .use { jacksonObjectMapper().readTree(it) }

    @Test
    fun `init transaction documents dc api response mode and expected origins`() {
        val responseModes = openApi.at("/components/schemas/ResponseMode/enum").map { it.asText() }.toSet()
        assertEquals(setOf("direct_post", "direct_post.jwt", "dc_api.jwt"), responseModes)

        val requestUriMethods = openApi.at("/components/schemas/RequestUriMethod/enum").map { it.asText() }.toSet()
        assertEquals(setOf("get", "post"), requestUriMethods)
        assertFalse("post_get" in requestUriMethods)

        val expectedOrigins = openApi.at("/components/schemas/InitTransaction/properties/expected_origins")
        assertEquals("array", expectedOrigins.path("type").asText())
        assertEquals(1, expectedOrigins.path("minItems").asInt())
        assertEquals("uri", expectedOrigins.at("/items/format").asText())
        assertEquals("^https://[^/?#@]+/?$", expectedOrigins.at("/items/pattern").asText())

        val verifierAttestations = openApi.at("/components/schemas/InitTransaction/properties/verifier_attestations")
        assertEquals("array", verifierAttestations.path("type").asText())
        assertEquals(1, verifierAttestations.path("minItems").asInt())
        assertEquals("#/components/schemas/VerifierAttestation", verifierAttestations.at("/items/\$ref").asText())

        val verifierAttestationFormats =
            openApi.at("/components/schemas/VerifierAttestationFormat/enum").map { it.asText() }.toSet()
        assertEquals(setOf("jwt"), verifierAttestationFormats)
        assertEquals("\\S", openApi.at("/components/schemas/VerifierAttestation/properties/data/pattern").asText())
        assertEquals(
            "^[A-Za-z][A-Za-z0-9+.-]*$",
            openApi.at("/components/schemas/AuthorizationRequestScheme/pattern").asText(),
        )
    }

    @Test
    fun `init transaction validation errors document current haip response mode error`() {
        val errors = openApi.at("/components/schemas/ValidationError/enum").map { it.asText() }.toSet()

        assertTrue("HaipNotSupported.ResponseModeDirectPostJwtOrDcApiJwtMustBeUsed" in errors)
        assertFalse("HaipNotSupported.ResponseModeDirectPostJwtMustBeUsed" in errors)
        assertTrue("MissingExpectedOrigins" in errors)
        assertTrue("InvalidExpectedOrigins" in errors)
        assertTrue("InvalidVerifierAttestations" in errors)
    }
}
