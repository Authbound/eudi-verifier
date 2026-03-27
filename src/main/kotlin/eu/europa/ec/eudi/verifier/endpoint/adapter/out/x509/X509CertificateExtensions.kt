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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.x509

import java.security.interfaces.ECPublicKey
import java.security.cert.X509Certificate

fun X509Certificate.isSelfSigned(): Boolean =
    subjectX500Principal == issuerX500Principal &&
        runCatching {
            verify(publicKey)
            true
        }.getOrElse { false }

fun List<X509Certificate>.dropRootCAIfPresent(): List<X509Certificate> =
    if (size > 1 && last().isSelfSigned()) dropLast(1)
    else this

fun X509Certificate.dnsSubjectAlternativeNames(): List<String> =
    subjectAlternativeNames
        ?.mapNotNull { san ->
            val type = san.getOrNull(0) as? Int
            val value = san.getOrNull(1) as? String
            value?.takeIf { type == 2 }
        }
        .orEmpty()

fun X509Certificate.matchesEcPublicKey(expected: ECPublicKey): Boolean {
    val actual = publicKey as? ECPublicKey ?: return false
    return actual.w == expected.w &&
        actual.params.curve == expected.params.curve &&
        actual.params.generator == expected.params.generator &&
        actual.params.order == expected.params.order &&
        actual.params.cofactor == expected.params.cofactor
}
