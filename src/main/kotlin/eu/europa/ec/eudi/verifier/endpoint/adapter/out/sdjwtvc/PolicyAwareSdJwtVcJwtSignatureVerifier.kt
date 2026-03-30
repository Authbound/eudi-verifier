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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.sdjwtvc

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.util.X509CertUtils
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.sdjwt.JwtSignatureVerifier
import eu.europa.ec.eudi.sdjwt.SdJwtVcSpec
import eu.europa.ec.eudi.sdjwt.VerificationError
import eu.europa.ec.eudi.sdjwt.asException
import eu.europa.ec.eudi.sdjwt.jsonObject
import eu.europa.ec.eudi.sdjwt.vc.SdJwtVcVerificationError.IssuerKeyVerificationError
import eu.europa.ec.eudi.sdjwt.vc.X509CertificateTrust
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.issuer.IssuerMetadataJwkSetResolver
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.issuer.IssuerMetadataNotAllowedException
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.issuer.verifySignedJwtWithJwkSet
import io.ktor.http.*
import java.security.cert.X509Certificate
import java.text.ParseException

internal class PolicyAwareSdJwtVcJwtSignatureVerifier(
    private val x509CertificateTrust: X509CertificateTrust<List<X509Certificate>>,
    private val issuerMetadataJwkSetResolver: IssuerMetadataJwkSetResolver,
) : JwtSignatureVerifier<SignedJWT> {

    override suspend fun checkSignature(jwt: String): SignedJWT? {
        val signedJwt = try {
            SignedJWT.parse(jwt)
        } catch (_: ParseException) {
            throw VerificationError.ParsingError.asException()
        }

        return when (val source = issuerKeySource(signedJwt)) {
            is IssuerPublicKeySource.X509CertChain -> verifyUsingX5c(signedJwt, source.chain)
            is IssuerPublicKeySource.Metadata -> verifyUsingIssuerMetadata(signedJwt, source.issuer)
            is IssuerPublicKeySource.Did -> raise(IssuerKeyVerificationError.UnsupportedVerificationMethod("did"))
        }
    }

    private suspend fun verifyUsingX5c(signedJwt: SignedJWT, chain: List<X509Certificate>): SignedJWT {
        if (!x509CertificateTrust.isTrusted(chain, signedJwt.jwtClaimsSet.jsonObject())) {
            raise(IssuerKeyVerificationError.UntrustedIssuerCertificate())
        }
        val jwk = JWK.parse(chain.first())
        return verify(signedJwt, JWKSet(jwk), useKeyId = false)
    }

    private suspend fun verifyUsingIssuerMetadata(signedJwt: SignedJWT, issuer: Url): SignedJWT {
        val jwkSet = try {
            issuerMetadataJwkSetResolver.resolve(issuer)
        } catch (_: IssuerMetadataNotAllowedException) {
            raise(IssuerKeyVerificationError.UnsupportedVerificationMethod("issuer-metadata"))
        } catch (error: Throwable) {
            raise(IssuerKeyVerificationError.IssuerMetadataResolutionFailure(error))
        }
        return verify(signedJwt, jwkSet, useKeyId = true)
    }

    private fun verify(signedJwt: SignedJWT, jwkSet: JWKSet, useKeyId: Boolean): SignedJWT =
        try {
            verifySignedJwtWithJwkSet(
                signedJwt = signedJwt,
                jwkSet = jwkSet,
                useKeyId = useKeyId,
                type = JOSEObjectType(SdJwtVcSpec.MEDIA_SUBTYPE_DC_SD_JWT),
                requiredClaims = setOf(SdJwtVcSpec.VCT),
            )
            signedJwt
        } catch (error: Throwable) {
            throw VerificationError.InvalidJwt(error).asException()
        }

    private fun raise(error: IssuerKeyVerificationError): Nothing =
        throw VerificationError.SdJwtVcError(error).asException()
}

private sealed interface IssuerPublicKeySource {
    data class Metadata(val issuer: Url) : IssuerPublicKeySource

    data class X509CertChain(val chain: List<X509Certificate>) : IssuerPublicKeySource

    data class Did(val issuer: String) : IssuerPublicKeySource
}

private fun issuerKeySource(jwt: SignedJWT): IssuerPublicKeySource {
    val certChain = jwt.header.x509CertChain.orEmpty().mapNotNull { X509CertUtils.parse(it.decode()) }
    val issuer = jwt.jwtClaimsSet.issuer
    val issuerUrl = issuer?.let { runCatching { Url(it) }.getOrNull() }
    val issuerScheme = issuerUrl?.protocol?.name

    return when {
        certChain.isNotEmpty() -> IssuerPublicKeySource.X509CertChain(certChain)
        issuerScheme == URLProtocol.HTTPS.name -> IssuerPublicKeySource.Metadata(checkNotNull(issuerUrl))
        issuerScheme == "did" -> IssuerPublicKeySource.Did(checkNotNull(issuer))
        else -> throw VerificationError.SdJwtVcError(
            IssuerKeyVerificationError.CannotDetermineIssuerVerificationMethod,
        ).asException()
    }
}
