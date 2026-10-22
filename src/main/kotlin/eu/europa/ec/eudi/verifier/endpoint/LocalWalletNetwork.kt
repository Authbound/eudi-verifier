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
package eu.europa.ec.eudi.verifier.endpoint

import eu.europa.ec.eudi.verifier.endpoint.adapter.out.http.OutboundPolicy
import org.springframework.core.env.Environment
import org.springframework.core.env.Profiles
import java.net.URI

/** A developer must opt in on a loopback listener; production never accepts local egress settings. */
internal fun localWalletOrigins(environment: Environment): Set<URI> {
    val configured = environment.getProperty("verifier.localWallet.allowedOrigins")?.trim().orEmpty()
    if (configured.isEmpty()) return emptySet()
    require(environment.acceptsProfiles(Profiles.of("local-wallet")) && !environment.acceptsProfiles(Profiles.of("prod", "production", "kms-x509-hash", "kms-san-dns"))) {
        "Local wallet origins require the non-production local-wallet profile"
    }
    require(environment.getProperty("server.address") == "127.0.0.1") {
        "The local wallet verifier must listen only on 127.0.0.1"
    }
    val origins = configured.split(',').map { URI(it.trim()) }.toSet()
    OutboundPolicy.localWallet(origins)
    return origins
}
