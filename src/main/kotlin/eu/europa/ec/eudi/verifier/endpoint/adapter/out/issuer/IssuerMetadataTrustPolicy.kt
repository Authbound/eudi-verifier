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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.issuer

import io.ktor.http.Url

internal data class IssuerMetadataNotAllowedException(val issuer: String) :
    IllegalStateException("Issuer '$issuer' is not configured for issuer-metadata verification")

internal class IssuerMetadataTrustPolicy(
    private val allowedIssuerPatterns: Set<Regex>,
) {

    val isEnabled: Boolean
        get() = allowedIssuerPatterns.isNotEmpty()

    fun isAllowed(url: Url): Boolean =
        allowedIssuerPatterns.any { it.matches(url.toString()) }

    fun requireAllowed(url: Url) {
        if (!isAllowed(url)) {
            throw IssuerMetadataNotAllowedException(url.toString())
        }
    }

    companion object {
        val Disabled = IssuerMetadataTrustPolicy(emptySet())
    }
}
