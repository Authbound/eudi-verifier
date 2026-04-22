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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.security

import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2TokenValidator
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import org.springframework.security.oauth2.jwt.*
import java.time.Duration

class AudienceAllowlistValidator(private val audiences: Set<String>) : OAuth2TokenValidator<Jwt> {
    override fun validate(token: Jwt): OAuth2TokenValidatorResult {
        return if (token.audience.any { audiences.contains(it) }) {
            OAuth2TokenValidatorResult.success()
        } else {
            val error = OAuth2Error(
                "invalid_token",
                "Token is missing required audience",
                null,
            )
            OAuth2TokenValidatorResult.failure(error)
        }
    }
}

class IssuerAllowlistValidator(private val issuers: Set<String>) : OAuth2TokenValidator<Jwt> {
    override fun validate(token: Jwt): OAuth2TokenValidatorResult {
        val issuer = token.issuer?.toString()
        return if (issuer != null && issuers.contains(issuer)) {
            OAuth2TokenValidatorResult.success()
        } else {
            val error = OAuth2Error(
                "invalid_token",
                "Token is missing required issuer",
                null,
            )
            OAuth2TokenValidatorResult.failure(error)
        }
    }
}

fun buildS2sJwtDecoder(
    jwksUrl: String,
    issuers: Set<String>,
    audiences: Set<String>,
    clockSkewSeconds: Long,
): ReactiveJwtDecoder {
    val decoder = NimbusReactiveJwtDecoder.withJwkSetUri(jwksUrl)
        .jwsAlgorithm(SignatureAlgorithm.ES256)
        .build()
    val timestampValidator = JwtTimestampValidator(Duration.ofSeconds(clockSkewSeconds))
    val issuerValidator = IssuerAllowlistValidator(issuers)
    val audienceValidator = AudienceAllowlistValidator(audiences)
    val validator = DelegatingOAuth2TokenValidator(timestampValidator, issuerValidator, audienceValidator)
    decoder.setJwtValidator(validator)
    return decoder
}
