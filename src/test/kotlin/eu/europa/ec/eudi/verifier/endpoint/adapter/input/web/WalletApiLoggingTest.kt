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
package eu.europa.ec.eudi.verifier.endpoint.adapter.input.web

import org.junit.jupiter.api.Test
import java.nio.file.Path
import kotlin.io.path.readText
import kotlin.test.assertFalse

class WalletApiLoggingTest {

    @Test
    fun `wallet api does not log raw wallet responses`() {
        val source = Path.of(
            "src/main/kotlin/eu/europa/ec/eudi/verifier/endpoint/adapter/input/web/WalletApi.kt",
        ).readText()

        assertFalse(source.contains("Wallet response:"))
        assertFalse(source.contains("\$walletResponse"))
    }
}
