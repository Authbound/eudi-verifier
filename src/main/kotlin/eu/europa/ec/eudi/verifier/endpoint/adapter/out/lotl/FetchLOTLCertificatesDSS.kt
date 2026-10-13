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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.lotl

import arrow.core.Either
import eu.europa.ec.eudi.verifier.endpoint.domain.TrustedListConfig
import eu.europa.ec.eudi.verifier.endpoint.port.out.lotl.FetchLOTLCertificates
import java.security.cert.X509Certificate

/** Online trusted-list loading stays fail closed until all linked download paths are protected. */
class FetchLOTLCertificatesDSS : FetchLOTLCertificates {
    override suspend fun invoke(trustedListConfig: TrustedListConfig): Either<Throwable, List<X509Certificate>> =
        Either.Left(IllegalStateException("Online LOTL loading is unsupported until every linked-download transport is protected"))
}

internal fun TrustedListConfig.matchesServiceType(serviceTypeIdentifier: String): Boolean =
    serviceTypeFilters.isEmpty() || serviceTypeFilters.any { serviceTypeIdentifier in it.serviceTypeIdentifiers }
