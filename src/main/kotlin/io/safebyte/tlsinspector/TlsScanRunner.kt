package io.safebyte.tlsinspector

import burp.api.montoya.MontoyaApi
import io.safebyte.tlsinspector.probes.AlpacaProbe
import io.safebyte.tlsinspector.probes.BeastProbe
import io.safebyte.tlsinspector.probes.CcsInjectionProbe
import io.safebyte.tlsinspector.probes.CertificateValidationProbe
import io.safebyte.tlsinspector.probes.CipherSuiteEnumerationProbe
import io.safebyte.tlsinspector.probes.CrimeProbe
import io.safebyte.tlsinspector.probes.DrownProbe
import io.safebyte.tlsinspector.probes.FallbackScsvProbe
import io.safebyte.tlsinspector.probes.FreakProbe
import io.safebyte.tlsinspector.probes.HeartbleedProbe
import io.safebyte.tlsinspector.probes.HrrAbuseProbe
import io.safebyte.tlsinspector.probes.LogjamCommonPrimeProbe
import io.safebyte.tlsinspector.probes.LogjamExportProbe
import io.safebyte.tlsinspector.probes.Lucky13Probe
import io.safebyte.tlsinspector.probes.PoodleProbe
import io.safebyte.tlsinspector.probes.ProtocolEnumerationProbe
import io.safebyte.tlsinspector.probes.RaccoonProbe
import io.safebyte.tlsinspector.probes.RobotProbe
import io.safebyte.tlsinspector.probes.Sweet32Probe
import io.safebyte.tlsinspector.probes.CaaDnsProbe
import io.safebyte.tlsinspector.probes.CrlRevocationProbe
import io.safebyte.tlsinspector.probes.CtLogProbe
import io.safebyte.tlsinspector.probes.HstsPreloadProbe
import io.safebyte.tlsinspector.probes.OcspRevocationProbe
import io.safebyte.tlsinspector.probes.OcspStaplingProbe
import io.safebyte.tlsinspector.probes.ProfileEvaluatorProbe
import io.safebyte.tlsinspector.probes.PqcKemProbe
import io.safebyte.tlsinspector.probes.TlsProbe
import io.safebyte.tlsinspector.probes.ZeroRttReplayProbe
import io.safebyte.tlsinspector.reporting.TlsIssueBuilder
import java.time.Instant
import java.util.LinkedHashMap
import java.util.concurrent.Executors
import java.util.concurrent.ThreadFactory
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

class TlsScanHandle internal constructor(
    val result: TlsScanResult,
    private val cancelFlag: () -> Unit,
    private val joinFn: () -> Unit
) {
    @Volatile private var done = false
    fun cancel() { cancelFlag(); }
    fun await(): TlsScanResult { joinFn(); done = true; return result }
    fun isRunning(): Boolean = !done
}

class TlsScanRunner(private val api: MontoyaApi) {

    private val history = LinkedHashMap<String, TlsScanResult>(16, 0.75f, true)
    private val activeScans = mutableSetOf<TlsScanHandle>()
    private val activeLock = Any()

    private val threadCounter = AtomicInteger(0)
    private val threadFactory = ThreadFactory { r ->
        Thread(r, "tls-scan-${threadCounter.incrementAndGet()}").apply { isDaemon = true }
    }

    fun start(
        host: String,
        port: Int,
        sniOverride: String?,
        budget: ScanBudget,
        profile: ScanProfile = ScanProfile.MOZILLA_INTERMEDIATE,
    ): TlsScanHandle {
        val sni = sniOverride.orEmpty().ifBlank { host }
        val target = "$host:$port"
        val result = TlsScanResult(target = target, startedAt = Instant.now())
        val cancelledFlag = AtomicBoolean(false)
        val ctx = ProbeContext(
            host = host, port = port, sni = sni, api = api, budget = budget,
            cancelled = { cancelledFlag.get() }, profile = profile,
        )
        val executor = Executors.newFixedThreadPool(budget.maxConcurrentHandshakes, threadFactory)

        val probes: List<TlsProbe> = listOf(
            // Informational
            ProtocolEnumerationProbe(),
            CipherSuiteEnumerationProbe(),
            CertificateValidationProbe(),
            // Vulnerability — MS A
            HeartbleedProbe(),
            PoodleProbe(),
            FreakProbe(),
            // Vulnerability — MS B
            Sweet32Probe(),
            DrownProbe(),
            BeastProbe(),
            Lucky13Probe(),
            CrimeProbe(),
            CcsInjectionProbe(),
            FallbackScsvProbe(),
            LogjamExportProbe(),
            LogjamCommonPrimeProbe(),
            // Vulnerability — MS C
            RobotProbe(),
            RaccoonProbe(),
            AlpacaProbe(),
            ZeroRttReplayProbe(),
            HrrAbuseProbe(),
            // MS D: revocation + reputation (run after cert capture)
            OcspRevocationProbe(),
            CrlRevocationProbe(),
            OcspStaplingProbe(),
            CtLogProbe(),
            CaaDnsProbe(),
            HstsPreloadProbe(),
            // MS D: compliance evaluator runs LAST (depends on all collected data)
            ProfileEvaluatorProbe(),
            // MS E: PQC Hybrid KEM probe (TLS 1.3 required — runs after protocol enum)
            PqcKemProbe(),
        )

        val mainThread = Thread({
            api.logging().logToOutput("[TLS Audit] Starting scan on $target (budget=${budget.name})")
            try {
                for (probe in probes) {
                    if (cancelledFlag.get()) break
                    try {
                        val probeResult = probe.runWithResult(ctx, result)
                        synchronized(result) {
                            // Informational probes (ProtocolEnum, CipherEnum, CertValidation) add
                            // their findings into result.findings themselves during run(). Vulnerability
                            // probes (Heartbleed, POODLE, FREAK) also add directly via result.findings.add().
                            // The ProbeResult.findings list mirrors what was added. To avoid double-adding,
                            // we only store probeResults here — findings are already in result.findings.
                            result.probeResults += probeResult
                        }
                        api.logging().logToOutput("[TLS Audit] ${probe.displayName}: ${probeResult.verdict.displayName}" +
                            (if (probeResult.message != null) " — ${probeResult.message}" else "") +
                            " (${probeResult.durationMs} ms)")
                    } catch (e: Exception) {
                        result.errors += "${probe.id} failed: ${e.message}"
                        api.logging().logToError("[TLS Audit] ${probe.id} failed: ${e.message}")
                    }
                }
            } finally {
                result.finishedAt = Instant.now()
                executor.shutdown()
                executor.awaitTermination(5, TimeUnit.SECONDS)
                synchronized(history) {
                    history[target] = result
                    while (history.size > TlsConfig.MAX_HISTORY) {
                        val oldest = history.keys.first(); history.remove(oldest)
                    }
                }

                // MS E: auto-push all findings to Burp's Issue Tracker
                val issueBuilder = TlsIssueBuilder(api)
                var issuesAdded = 0
                synchronized(result) {
                    for (finding in result.findings) {
                        try {
                            issueBuilder.reportToBurp(finding, ctx.host, ctx.port)
                            issuesAdded++
                        } catch (e: Exception) {
                            api.logging().logToError(
                                "[TlsAudit] Failed to add issue '${finding.title}' to site map: ${e.message}"
                            )
                        }
                    }
                }
                api.logging().logToOutput(
                    "[TlsAudit] Scan complete. ${result.findings.size} findings, $issuesAdded Burp issues added."
                )

                // MS E: inject CT-discovered subdomains into Burp site map
                if (ctx.injectCtIntoSiteMap && result.ctSubdomains.isNotEmpty()) {
                    val MAX_CT_INJECTIONS = 200
                    var ctAdded = 0
                    for (sub in result.ctSubdomains.take(MAX_CT_INJECTIONS)) {
                        try {
                            val req = burp.api.montoya.http.message.requests.HttpRequest
                                .httpRequestFromUrl("https://$sub/")
                            val rr = burp.api.montoya.http.message.HttpRequestResponse
                                .httpRequestResponse(req, null)
                            api.siteMap().add(rr)
                            ctAdded++
                        } catch (e: Exception) {
                            api.logging().logToError(
                                "[TlsAudit] Failed to add CT subdomain $sub to site map: ${e.message}"
                            )
                        }
                    }
                    api.logging().logToOutput(
                        "[TlsAudit] Added $ctAdded/${result.ctSubdomains.size} CT subdomains to Burp site map"
                    )
                }
            }
        }, "tls-scan-main-${threadCounter.incrementAndGet()}").apply { isDaemon = true }

        val handle = TlsScanHandle(
            result = result,
            cancelFlag = {
                cancelledFlag.set(true)
                executor.shutdownNow()
            },
            joinFn = { mainThread.join(60_000) }
        )
        synchronized(activeLock) { activeScans += handle }
        mainThread.start()
        return handle
    }

    /** Called from extension unload — cancels all active scans + clears history. */
    fun shutdown() {
        synchronized(activeLock) {
            activeScans.forEach { it.cancel() }
            activeScans.clear()
        }
        synchronized(history) { history.clear() }
    }
}
