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

import software.amazon.awssdk.http.AbortableInputStream
import software.amazon.awssdk.http.ExecutableHttpRequest
import software.amazon.awssdk.http.HttpExecuteRequest
import software.amazon.awssdk.http.HttpExecuteResponse
import software.amazon.awssdk.http.SdkHttpClient
import software.amazon.awssdk.http.SdkHttpResponse
import java.io.ByteArrayInputStream
import java.net.URI

/** Only the SDK-derived regional KMS endpoint may receive signed AWS requests. */
class BoundedAwsHttpClient(endpoint: URI) : SdkHttpClient {
    internal val destinationPolicy = OutboundPolicy.exactPublic(endpoint.resolve("/"), "POST")
    private val transport = BoundedHttpTransport(destinationPolicy, true)
    override fun prepareRequest(request: HttpExecuteRequest): ExecutableHttpRequest = object : ExecutableHttpRequest {
        private val cancellation = BoundedHttpTransport.Cancellation()
        override fun abort() = cancellation.abort()
        override fun call(): HttpExecuteResponse {
            val source = request.httpRequest()
            val uri = source.uri
            val headers = source.headers().flatMap { (name, values) -> values.map { name to it } }
            val host = headers.filter { it.first.equals("Host", true) }
            require(host.all { it.second.equals(uri.rawAuthority, true) }) { "AWS signed Host differs from endpoint" }
            val body = request.contentStreamProvider().map {
                    provider ->
                provider.newStream().use(BoundedHttpTransport::readBounded)
            }.orElse(byteArrayOf())
            val response = transport.execute(
                uri,
                source.method().name,
                headers.filterNot { it.first.equals("Host", true) },
                body,
                cancellation,
            )
            return HttpExecuteResponse.builder()
                .response(
                    SdkHttpResponse.builder().statusCode(
                        response.status,
                    ).headers(response.headers.groupBy({ it.first }, { it.second })).build(),
                )
                .responseBody(AbortableInputStream.create(ByteArrayInputStream(response.body))).build()
        }
    }
    override fun close() = Unit
}
