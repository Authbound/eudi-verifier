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

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.Ed25519Verifier
import com.nimbusds.jose.crypto.MACVerifier
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKMatcher
import com.nimbusds.jose.jwk.JWKSelector
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.OctetSequenceKey
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.BadJOSEException
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier
import com.nimbusds.jose.proc.JOSEObjectTypeVerifier
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.PlainJWT
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.BadJWTException
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier
import com.nimbusds.jwt.proc.JWTProcessor
import java.text.ParseException

internal fun verifySignedJwtWithJwkSet(
    signedJwt: SignedJWT,
    jwkSet: JWKSet,
    useKeyId: Boolean,
    type: JOSEObjectType? = null,
    requiredClaims: Set<String> = emptySet(),
) {
    val typeVerifier = type?.let { DefaultJOSEObjectTypeVerifier<SecurityContext>(it) }
    val claimsVerifier = requiredClaims.takeIf { it.isNotEmpty() }?.let {
        DefaultJWTClaimsVerifier<SecurityContext>(JWTClaimsSet.Builder().build(), it)
    }
    val processor = JwkSourceJwtProcessor(typeVerifier, claimsVerifier, ImmutableJWKSet(jwkSet), useKeyId)
    processor.process(signedJwt, null)
}

private open class JwkSourceJwtProcessor<C : SecurityContext>(
    private val typeVerifier: JOSEObjectTypeVerifier<C>? = null,
    private val claimSetVerifier: JWTClaimsSetVerifier<C>? = null,
    private val jwkSource: JWKSource<C>,
    private val useKeyId: Boolean,
) : JWTProcessor<C> {

    private fun notSupported(): Nothing = throw BadJOSEException("Only SignedJWTs are supported")

    override fun process(plainJWT: PlainJWT, context: C?): JWTClaimsSet? = notSupported()

    override fun process(encryptedJWT: EncryptedJWT, context: C?): JWTClaimsSet? = notSupported()

    override fun process(jwtString: String, context: C?): JWTClaimsSet? =
        process(JWTParser.parse(jwtString), context)

    override fun process(jwt: JWT, context: C?): JWTClaimsSet? =
        when (jwt) {
            is SignedJWT -> process(jwt, context)
            else -> notSupported()
        }

    override fun process(signedJWT: SignedJWT, context: C?): JWTClaimsSet {
        typeVerifier?.verify(signedJWT.header.type, context)

        val claimsSet = signedJwtClaimsSet(signedJWT)
        val matcher =
            if (useKeyId) {
                JWKMatcher.forJWSHeader(signedJWT.header)
            } else {
                JWKMatcher.forJWSHeader(signedJWT.header).withoutKeyId()
            }
        val selector = JWKSelector(matcher)
        val jwks = jwkSource.get(selector, context)

        if (jwks.isNullOrEmpty()) {
            throw BadJOSEException("Signed JWT rejected: Another algorithm expected, or no matching key(s) found")
        }

        for (jwk in jwks) {
            val verifier = jwsVerifierFor(signedJWT.header.algorithm, jwk)
            if (signedJWT.verify(verifier)) {
                claimSetVerifier?.verify(claimsSet, context)
                return claimsSet
            }
        }

        throw BadJOSEException("Signed JWT rejected: Invalid signature or no matching verifier(s) found")
    }

    private fun signedJwtClaimsSet(signedJWT: SignedJWT): JWTClaimsSet =
        try {
            signedJWT.jwtClaimsSet
        } catch (error: ParseException) {
            throw BadJWTException(error.message, error)
        }

    private fun jwsVerifierFor(algorithm: com.nimbusds.jose.JWSAlgorithm, jwk: JWK): JWSVerifier =
        when (algorithm) {
            in com.nimbusds.jose.JWSAlgorithm.Family.HMAC_SHA -> MACVerifier(jwk.expectIs<OctetSequenceKey>())
            in com.nimbusds.jose.JWSAlgorithm.Family.RSA -> RSASSAVerifier(jwk.expectIs<RSAKey>())
            in com.nimbusds.jose.JWSAlgorithm.Family.EC -> ECDSAVerifier(jwk.expectIs<ECKey>())
            in com.nimbusds.jose.JWSAlgorithm.Family.ED -> Ed25519Verifier(jwk.expectIs<OctetKeyPair>())
            else -> throw BadJOSEException("Unsupported JWS algorithm $algorithm")
        }

    private inline fun <reified T> JWK.expectIs(): T =
        if (this is T) {
            this
        } else {
            throw BadJOSEException("Expected a JWK of type ${T::class.java.simpleName}")
        }
}

private fun JWKMatcher.withoutKeyId(): JWKMatcher =
    JWKMatcher.Builder(this)
        .keyID(null)
        .withKeyIDOnly(false)
        .build()
