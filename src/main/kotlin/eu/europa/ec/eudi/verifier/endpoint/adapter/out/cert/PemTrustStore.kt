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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert

import java.security.KeyStore
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * Builds an in-memory trust store from PEM certificates, so issuer trust anchors can be
 * configured as plain values instead of mounted keystore files. Env files often carry the
 * PEM on one line with escaped newlines, so `\n` is accepted as a line break.
 */
internal fun pemTrustStore(pem: String): KeyStore {
    val certificates = try {
        CertificateFactory.getInstance("X.509")
            .generateCertificates(pem.replace("\\n", "\n").byteInputStream())
            .filterIsInstance<X509Certificate>()
    } catch (error: CertificateException) {
        throw IllegalArgumentException("Trust anchors are not valid PEM certificates", error)
    }
    require(certificates.isNotEmpty()) { "Trust anchors contain no PEM certificates" }
    return KeyStore.getInstance("PKCS12").apply {
        load(null, null)
        certificates.forEachIndexed { index, certificate -> setCertificateEntry("trust-anchor-$index", certificate) }
    }
}
