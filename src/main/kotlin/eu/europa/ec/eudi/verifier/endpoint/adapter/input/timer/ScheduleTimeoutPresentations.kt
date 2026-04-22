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
package eu.europa.ec.eudi.verifier.endpoint.adapter.input.timer

import eu.europa.ec.eudi.verifier.endpoint.port.input.TimeoutPresentations
import io.micrometer.core.instrument.Metrics
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.scheduling.annotation.EnableScheduling
import org.springframework.scheduling.annotation.SchedulingConfigurer
import org.springframework.scheduling.config.ScheduledTaskRegistrar
import kotlin.time.Duration

@EnableScheduling
class ScheduleTimeoutPresentations(
    private val timeoutPresentations: TimeoutPresentations,
    private val interval: Duration,
) : SchedulingConfigurer {

    private val logger: Logger = LoggerFactory.getLogger(ScheduleTimeoutPresentations::class.java)
    private val runCounter = Metrics.counter("eudi_presentations_timeout_sweeper_runs_total")
    private val expiredCounter = Metrics.counter("eudi_presentations_timeout_sweeper_expired_total")
    private val errorCounter = Metrics.counter("eudi_presentations_timeout_sweeper_errors_total")

    override fun configureTasks(taskRegistrar: ScheduledTaskRegistrar) {
        taskRegistrar.addFixedRateTask(interval) {
            runBlocking(Dispatchers.IO) {
                runCounter.increment()
                try {
                    timeoutPresentations().also {
                        expiredCounter.increment(it.size.toDouble())
                        if (it.isNotEmpty()) logger.info("Timed out ${it.size} presentations")
                    }
                } catch (t: Throwable) {
                    errorCounter.increment()
                    logger.warn("Failed to sweep timed out presentations", t)
                    throw t
                }
            }
        }
    }
}
