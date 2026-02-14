package eu.europa.ec.eudi.verifier.endpoint

import org.springframework.context.ApplicationContextInitializer
import org.springframework.context.ConfigurableApplicationContext
import org.springframework.test.context.support.TestPropertyValues
import org.testcontainers.containers.GenericContainer
import org.testcontainers.utility.DockerImageName

internal object RedisTestContainer {
    private val container = GenericContainer(DockerImageName.parse("redis:7.2-alpine"))
        .withExposedPorts(6379)

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
