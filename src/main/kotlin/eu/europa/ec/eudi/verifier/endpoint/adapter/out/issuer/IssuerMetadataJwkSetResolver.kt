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

import com.nimbusds.jose.jwk.JWKSet
import eu.europa.ec.eudi.sdjwt.vc.GetSdJwtVcIssuerMetadataOps
import io.ktor.client.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*

class IssuerMetadataJwkSetResolver internal constructor(
    private val httpClient: HttpClient,
    private val trustPolicy: IssuerMetadataTrustPolicy,
) {

    suspend fun resolve(issuer: Url): JWKSet {
        trustPolicy.requireAllowed(issuer)
        val metadata = with(GetSdJwtVcIssuerMetadataOps) {
            httpClient.getSdJwtVcIssuerMetadata(issuer)
        } ?: error("Unable to resolve SD-JWT VC issuer metadata for '$issuer'")

        metadata.jwks?.let { return JWKSet.parse(it.toString()) }

        val jwksUri = metadata.jwksUri?.let(::Url)
            ?: error("Issuer metadata for '$issuer' does not contain 'jwks' or 'jwks_uri'")
        trustPolicy.requireAllowed(jwksUri)

        val body = httpClient.get(jwksUri).bodyAsText()
        return JWKSet.parse(body)
    }
}
