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

import org.springframework.core.io.DefaultResourceLoader
import org.springframework.core.io.Resource

fun localResource(location: String): Resource {
    require(!location.contains(':') || location.startsWith("classpath:") || location.startsWith("file:")) {
        "Remote resource loading is forbidden"
    }
    if (location.startsWith("file:")) {
        val uri = java.net.URI(location)
        require(uri.authority.isNullOrEmpty() && uri.query == null && uri.fragment == null) { "Only local file resources are supported" }
    }
    require(!location.startsWith("//") && !location.startsWith("\\\\")) { "Network resource paths are forbidden" }
    return DefaultResourceLoader().getResource(location)
}
