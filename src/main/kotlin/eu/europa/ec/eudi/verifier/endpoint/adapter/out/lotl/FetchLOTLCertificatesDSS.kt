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
import eu.europa.ec.eudi.verifier.endpoint.domain.KeyStoreConfig
import eu.europa.ec.eudi.verifier.endpoint.domain.TrustedListConfig
import eu.europa.ec.eudi.verifier.endpoint.port.out.lotl.FetchLOTLCertificates
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader
import eu.europa.esig.dss.spi.client.http.DataLoader
import eu.europa.esig.dss.spi.client.http.DSSCacheFileLoader
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource
import eu.europa.esig.dss.tsl.cache.CacheCleaner
import eu.europa.esig.dss.tsl.function.GrantedOrRecognizedAtNationalLevelTrustAnchorPeriodPredicate
import eu.europa.esig.dss.tsl.job.TLValidationJob
import eu.europa.esig.dss.tsl.source.LOTLSource
import eu.europa.esig.dss.tsl.sync.ExpirationAndSignatureCheckStrategy
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.withContext
import org.apache.hc.client5.http.DnsResolver
import org.apache.hc.client5.http.SystemDefaultDnsResolver
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder
import org.apache.hc.client5.http.io.HttpClientConnectionManager
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.DisposableBean
import org.springframework.core.io.DefaultResourceLoader
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.URI
import java.net.UnknownHostException
import java.nio.file.Files
import java.security.cert.X509Certificate
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.function.Predicate
import kotlin.time.measureTimedValue

private val logger: Logger = LoggerFactory.getLogger(FetchLOTLCertificatesDSS::class.java)

class FetchLOTLCertificatesDSS(
    private val executorService: ExecutorService = Executors.newFixedThreadPool(4),
) : FetchLOTLCertificates, DisposableBean {
    private val dispatcher = executorService.asCoroutineDispatcher()

    override fun destroy() {
        dispatcher.close()
    }

    override suspend fun invoke(
        trustedListConfig: TrustedListConfig,
    ): Either<Throwable, List<X509Certificate>> = Either.catch {
        val trustedListsCertificateSource = TrustedListsCertificateSource()

        val tlCacheDirectory = Files.createTempDirectory("lotl-cache").toFile()

        val offlineLoader: DSSCacheFileLoader = FileCacheDataLoader().apply {
            setCacheExpirationTime(24 * 60 * 60 * 1000)
            setFileCacheDirectory(tlCacheDirectory)
            dataLoader = IgnoreDataLoader()
        }

        val onlineLoader: DSSCacheFileLoader = FileCacheDataLoader().apply {
            setCacheExpirationTime(24 * 60 * 60 * 1000)
            setFileCacheDirectory(tlCacheDirectory)
            dataLoader = SafeTrustedListDataLoader()
        }

        val cacheCleaner = CacheCleaner().apply {
            setCleanMemory(true)
            setCleanFileSystem(true)
            setDSSFileLoader(offlineLoader)
        }

        val validationJob = TLValidationJob().apply {
            setListOfTrustedListSources(lotlSource(trustedListConfig))
            setOfflineDataLoader(offlineLoader)
            setOnlineDataLoader(onlineLoader)
            setTrustedListCertificateSource(trustedListsCertificateSource)
            setSynchronizationStrategy(ExpirationAndSignatureCheckStrategy())
            setCacheCleaner(cacheCleaner)
            setExecutorService(executorService)
        }

        logger.info("Starting validation job")
        val (certs, duration) = measureTimedValue {
            withContext(dispatcher) {
                validationJob.onlineRefresh()
            }

            trustedListsCertificateSource.certificates.map {
                it.certificate
            }
        }
        logger.info("Finished validation job in $duration")
        certs
    }

    private suspend fun lotlSource(
        trustedListConfig: TrustedListConfig,
    ): LOTLSource = LOTLSource().apply {
        url = trustedListConfig.location.toExternalForm()
        trustedListConfig.keystoreConfig
            ?.let { lotlCertificateSource(it).getOrNull() }
            ?.let { certificateSource = it }
        isPivotSupport = true
        trustAnchorValidityPredicate = GrantedOrRecognizedAtNationalLevelTrustAnchorPeriodPredicate()
        tlVersions = listOf(5, 6)
        trustedListConfig.serviceTypeFilters.takeIf { it.isNotEmpty() }?.let {
            trustServicePredicate = Predicate { tspServiceType ->
                trustedListConfig.matchesServiceType(tspServiceType.serviceInformation.serviceTypeIdentifier)
            }
        }
    }

    private suspend fun lotlCertificateSource(keystoreConfig: KeyStoreConfig): Either<Throwable, KeyStoreCertificateSource> =
        withContext(dispatcher + CoroutineName("LotlCertificateSource-${keystoreConfig.keystorePath}")) {
            Either.catch {
                val resource = DefaultResourceLoader().getResource(keystoreConfig.keystorePath)
                KeyStoreCertificateSource(
                    resource.inputStream,
                    keystoreConfig.keystoreType,
                    keystoreConfig.keystorePassword?.toCharArray(),
                )
            }
        }
}

internal fun TrustedListConfig.matchesServiceType(serviceTypeIdentifier: String): Boolean =
    serviceTypeFilters.isEmpty() || serviceTypeFilters.any { serviceTypeIdentifier in it.serviceTypeIdentifiers }

internal class SafeTrustedListDataLoader : CommonsDataLoader() {
    init {
        setRedirectsEnabled(false)
    }

    override fun get(url: String): ByteArray {
        requirePublicHttpsUrl(url)
        return super.get(url)
    }

    override fun get(urls: MutableList<String>): DataLoader.DataAndUrl {
        urls.forEach(::requirePublicHttpsUrl)
        return super.get(urls)
    }

    override fun post(url: String, content: ByteArray): ByteArray {
        requirePublicHttpsUrl(url)
        return super.post(url, content)
    }

    override fun getConnectionManager(): HttpClientConnectionManager =
        PoolingHttpClientConnectionManagerBuilder.create()
            .setDnsResolver(PublicOnlyDnsResolver)
            .setTlsSocketStrategy(getTlsSocketStrategy())
            .setDefaultSocketConfig(getSocketConfig())
            .setMaxConnTotal(connectionsMaxTotal)
            .setMaxConnPerRoute(connectionsMaxPerRoute)
            .build()
}

internal object PublicOnlyDnsResolver : DnsResolver {
    override fun resolve(host: String): Array<InetAddress> =
        SystemDefaultDnsResolver.INSTANCE.resolve(host).also { addresses ->
            if (addresses.any(InetAddress::isBlockedFetchAddress)) {
                throw UnknownHostException("trusted list host resolves to a non-public address")
            }
        }

    override fun resolveCanonicalHostname(host: String): String =
        SystemDefaultDnsResolver.INSTANCE.resolveCanonicalHostname(host)
}

private fun requirePublicHttpsUrl(value: String) {
    val uri = URI(value)
    require(uri.scheme == "https") { "trusted list URL must use https" }
    require(uri.userInfo == null) { "trusted list URL must not include userinfo" }
    val host = requireNotNull(uri.host?.takeIf { it.isNotBlank() }) {
        "trusted list URL must include a host"
    }
    PublicOnlyDnsResolver.resolve(host)
}

private fun InetAddress.isBlockedFetchAddress(): Boolean =
    isAnyLocalAddress ||
        isLoopbackAddress ||
        isLinkLocalAddress ||
        isSiteLocalAddress ||
        isMulticastAddress ||
        isSpecialIpv4() ||
        isUniqueLocalIpv6() ||
        isMappedBlockedIpv4()

private fun InetAddress.isSpecialIpv4(): Boolean {
    if (this !is Inet4Address) return false
    val bytes = address.map { it.toInt() and 0xff }
    return bytes[0] == 0 ||
        bytes[0] >= 224 ||
        bytes[0] == 10 ||
        bytes[0] == 127 ||
        bytes[0] == 169 && bytes[1] == 254 ||
        bytes[0] == 172 && bytes[1] in 16..31 ||
        bytes[0] == 192 && bytes[1] == 168 ||
        bytes[0] == 100 && bytes[1] in 64..127 ||
        bytes[0] == 192 && bytes[1] == 0 && bytes[2] == 0 ||
        bytes[0] == 198 && bytes[1] in 18..19
}

private fun InetAddress.isUniqueLocalIpv6(): Boolean =
    this is Inet6Address && address.first().toInt() and 0xfe == 0xfc

private fun InetAddress.isMappedBlockedIpv4(): Boolean =
    this is Inet6Address &&
        address.take(10).all { it.toInt() == 0 } &&
        address[10].toInt() == -1 &&
        address[11].toInt() == -1 &&
        InetAddress.getByAddress(address.copyOfRange(12, 16)).isBlockedFetchAddress()
