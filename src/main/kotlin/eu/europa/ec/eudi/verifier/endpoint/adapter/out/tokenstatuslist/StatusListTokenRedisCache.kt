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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.tokenstatuslist

import eu.europa.ec.eudi.statium.StatusListTokenClaims
import eu.europa.ec.eudi.statium.misc.StatiumJson
import eu.europa.ec.eudi.verifier.endpoint.domain.Clock
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import org.springframework.data.redis.core.ReactiveStringRedisTemplate
import kotlinx.coroutines.reactor.awaitSingle
import kotlinx.coroutines.reactor.awaitSingleOrNull
import java.security.MessageDigest
import kotlin.time.Duration
import kotlin.time.Instant
import kotlin.time.toJavaDuration

class StatusListTokenRedisCache(
    private val redis: ReactiveStringRedisTemplate,
    private val clock: Clock,
) : StatusListTokenCache {

    override suspend fun get(uri: String, at: Instant?): StatusListTokenClaims? {
        val payload = redis.opsForValue().get(key(uri, at)).awaitSingleOrNull() ?: return null
        return StatiumJson.decodeFromString(StatusListTokenClaims.serializer(), payload)
    }

    override suspend fun put(uri: String, at: Instant?, claims: StatusListTokenClaims) {
        val ttl = claims.cacheDuration(clock.now()) ?: return
        val payload = StatiumJson.encodeToString(claims)
        redis.opsForValue().set(key(uri, at), payload, ttl.toJavaDuration()).awaitSingle()
    }

    private fun key(uri: String, at: Instant?): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(uri.toByteArray())
        val digestHex = digest.joinToString("") { byte -> "%02x".format(byte) }
        val atLabel = at?.epochSeconds?.toString() ?: "now"
        return "status-list-token:$atLabel:$digestHex"
    }

    private fun StatusListTokenClaims.cacheDuration(now: Instant): Duration? {
        val ttl = timeToLive?.value
        val exp = expirationTime?.let { it - now }
        val duration = when {
            ttl != null && exp != null -> minOf(ttl, exp)
            ttl != null -> ttl
            exp != null -> exp
            else -> null
        }
        return duration?.takeIf { it.isPositive() }
    }
}
