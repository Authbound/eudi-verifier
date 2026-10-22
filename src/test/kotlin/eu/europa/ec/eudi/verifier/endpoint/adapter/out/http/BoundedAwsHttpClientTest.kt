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
package eu.europa.ec.eudi.verifier.endpoint.adapter.out.http

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import software.amazon.awssdk.http.SdkHttpFullRequest
import software.amazon.awssdk.http.SdkHttpMethod
import software.amazon.awssdk.regions.Region
import software.amazon.awssdk.services.kms.endpoints.KmsEndpointParams
import software.amazon.awssdk.services.kms.endpoints.KmsEndpointProvider
import java.net.InetAddress
import java.net.URI

class BoundedAwsHttpClientTest {
    @Test
    fun `SDK regional endpoint and serialized root request share exact POST authority`() {
        for (region in listOf("eu-north-1", "us-east-1", "us-gov-west-1", "cn-north-1")) {
            val endpoint = KmsEndpointProvider.defaultProvider().resolveEndpoint(
                KmsEndpointParams.builder().region(Region.of(region)).useFips(false).useDualStack(false).build(),
            ).join().url()
            val request = SdkHttpFullRequest.builder().uri(endpoint).encodedPath("/").method(SdkHttpMethod.POST).build()
            val client = BoundedAwsHttpClient(endpoint)
            client.destinationPolicy.bind(request.uri, request.method().name) { arrayOf(InetAddress.getByAddress(byteArrayOf(8, 8, 8, 8))) }
            assertThrows(IllegalArgumentException::class.java) {
                client.destinationPolicy.bind(
                    URI("https://other.example/"),
                    "POST",
                ) { arrayOf(InetAddress.getByAddress(byteArrayOf(8, 8, 8, 8))) }
            }
            assertThrows(IllegalArgumentException::class.java) {
                client.destinationPolicy.bind(request.uri, "GET") { arrayOf(InetAddress.getByAddress(byteArrayOf(8, 8, 8, 8))) }
            }
            client.close()
        }
    }
}
