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

import org.springframework.boot.test.util.TestPropertyValues
import org.springframework.context.ApplicationContextInitializer
import org.springframework.context.ConfigurableApplicationContext
import org.testcontainers.DockerClientFactory
import org.testcontainers.containers.GenericContainer
import org.testcontainers.utility.DockerImageName

internal object RedisTestContainer {
    private val container = GenericContainer(DockerImageName.parse("redis:7.2-alpine"))
        .withExposedPorts(6379)

    fun isDockerAvailable(): Boolean =
        runCatching { DockerClientFactory.instance().isDockerAvailable() }.getOrDefault(false)

    fun startIfNeeded() {
        if (!container.isRunning) {
            container.start()
        }
    }

    val host: String
        get() {
            startIfNeeded()
            return container.host
        }

    val port: Int
        get() {
            startIfNeeded()
            return container.getMappedPort(6379)
        }

    fun redisUrl(): String = "redis://$host:$port"
}

internal class RedisTestContainerInitializer : ApplicationContextInitializer<ConfigurableApplicationContext> {
    override fun initialize(applicationContext: ConfigurableApplicationContext) {
        RedisTestContainer.startIfNeeded()
        TestPropertyValues.of(
            "spring.data.redis.url=${RedisTestContainer.redisUrl()}",
        ).applyTo(applicationContext.environment)
    }
}
