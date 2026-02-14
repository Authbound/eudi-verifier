package eu.europa.ec.eudi.verifier.endpoint.adapter.out.kms

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.jca.JCAContext
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.util.Base64URL
import software.amazon.awssdk.core.SdkBytes
import software.amazon.awssdk.services.kms.KmsClient
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse
import software.amazon.awssdk.services.kms.model.KeySpec
import software.amazon.awssdk.services.kms.model.KeyUsageType
import software.amazon.awssdk.services.kms.model.MessageType
import software.amazon.awssdk.services.kms.model.SignRequest
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.interfaces.ECPublicKey
import java.security.spec.X509EncodedKeySpec

internal data class KmsSigningMaterial(
    val jwk: ECKey,
    val signer: JWSSigner,
)

internal fun loadKmsSigningMaterial(
    kms: KmsClient,
    keyId: String,
    algorithm: JWSAlgorithm,
    kidOverride: String?,
): KmsSigningMaterial {
    val publicKeyResponse = kms.getPublicKey { it.keyId(keyId) }
    val jwk = publicKeyResponse.toEcJwk(algorithm, kidOverride)
    val signer = AwsKmsSigner(kms, publicKeyResponse.keyId() ?: keyId, algorithm)
    return KmsSigningMaterial(jwk, signer)
}

private fun GetPublicKeyResponse.toEcJwk(
    algorithm: JWSAlgorithm,
    kidOverride: String?,
): ECKey {
    require(keyUsage() == KeyUsageType.SIGN_VERIFY) { "KMS key usage must be SIGN_VERIFY" }
    val curve = keySpec().toCurve()
    val expectedCurve = algorithm.toExpectedCurve()
    require(curve == expectedCurve) {
        "KMS key spec ${keySpec()} is incompatible with JWS algorithm ${algorithm.name}"
    }

    val publicKey = publicKey().toECPublicKey()
    val kid = kidOverride?.takeIf { it.isNotBlank() } ?: keyId()

    return ECKey.Builder(curve, publicKey)
        .keyUse(KeyUse.SIGNATURE)
        .keyID(kid)
        .algorithm(algorithm)
        .build()
}

private fun KeySpec.toCurve(): Curve =
    when (this) {
        KeySpec.ECC_NIST_P256 -> Curve.P_256
        KeySpec.ECC_NIST_P384 -> Curve.P_384
        KeySpec.ECC_NIST_P521 -> Curve.P_521
        else -> error("Unsupported KMS key spec: $this")
    }

private fun JWSAlgorithm.toExpectedCurve(): Curve =
    when (this) {
        JWSAlgorithm.ES256 -> Curve.P_256
        JWSAlgorithm.ES384 -> Curve.P_384
        JWSAlgorithm.ES512 -> Curve.P_521
        else -> error("Unsupported JWS algorithm for KMS signing: ${name}")
    }

private fun SdkBytes.toECPublicKey(): ECPublicKey {
    val spec = X509EncodedKeySpec(asByteArray())
    val keyFactory = KeyFactory.getInstance("EC")
    return keyFactory.generatePublic(spec) as ECPublicKey
}

internal class AwsKmsSigner(
    private val kms: KmsClient,
    private val keyId: String,
    private val algorithm: JWSAlgorithm,
) : JWSSigner {

    private val jcaContext = JCAContext()

    override fun getJCAContext(): JCAContext = jcaContext

    override fun supportedJWSAlgorithms(): MutableSet<JWSAlgorithm> = mutableSetOf(algorithm)

    override fun sign(header: JWSHeader, signingInput: ByteArray): Base64URL {
        val digest = MessageDigest.getInstance(algorithm.toDigestAlgorithm()).digest(signingInput)
        val signature = kms.sign(
            SignRequest.builder()
                .keyId(keyId)
                .message(SdkBytes.fromByteArray(digest))
                .messageType(MessageType.DIGEST)
                .signingAlgorithm(algorithm.toKmsSigningAlgorithm())
                .build(),
        ).signature().asByteArray()

        val rawSignature = if (algorithm.name.startsWith("ES")) {
            transcodeSignatureToConcat(signature, algorithm.signatureLengthBytes())
        } else {
            signature
        }

        return Base64URL.encode(rawSignature)
    }
}

private fun JWSAlgorithm.toKmsSigningAlgorithm(): SigningAlgorithmSpec =
    when (this) {
        JWSAlgorithm.ES256 -> SigningAlgorithmSpec.ECDSA_SHA_256
        JWSAlgorithm.ES384 -> SigningAlgorithmSpec.ECDSA_SHA_384
        JWSAlgorithm.ES512 -> SigningAlgorithmSpec.ECDSA_SHA_512
        else -> error("Unsupported JWS algorithm for KMS signing: ${name}")
    }

private fun JWSAlgorithm.toDigestAlgorithm(): String =
    when (this) {
        JWSAlgorithm.ES256 -> "SHA-256"
        JWSAlgorithm.ES384 -> "SHA-384"
        JWSAlgorithm.ES512 -> "SHA-512"
        else -> error("Unsupported JWS algorithm for KMS signing: ${name}")
    }

private fun JWSAlgorithm.signatureLengthBytes(): Int =
    when (this) {
        JWSAlgorithm.ES256 -> 64
        JWSAlgorithm.ES384 -> 96
        JWSAlgorithm.ES512 -> 132
        else -> error("Unsupported JWS algorithm for KMS signing: ${name}")
    }

// Converts ASN.1 DER ECDSA signature to raw R|S format (P1363)
private fun transcodeSignatureToConcat(derSignature: ByteArray, outputLength: Int): ByteArray {
    if (derSignature.size < 8 || derSignature[0] != 0x30.toByte()) {
        throw IllegalArgumentException("Invalid DER signature format")
    }

    var offset = 2
    var rLength = derSignature[offset + 1].toInt()
    var rOffset = offset + 2
    if (rLength < 0) rLength += 256
    if (derSignature[rOffset] == 0x00.toByte() && rLength > 0) {
        rOffset++
        rLength--
    }

    offset += derSignature[offset + 1].toInt() + 2
    var sLength = derSignature[offset + 1].toInt()
    var sOffset = offset + 2
    if (sLength < 0) sLength += 256
    if (derSignature[sOffset] == 0x00.toByte() && sLength > 0) {
        sOffset++
        sLength--
    }

    val len = outputLength / 2
    val concatSignature = ByteArray(outputLength)
    System.arraycopy(derSignature, rOffset, concatSignature, len - rLength, rLength)
    System.arraycopy(derSignature, sOffset, concatSignature, outputLength - sLength, sLength)
    return concatSignature
}
