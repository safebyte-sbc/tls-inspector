package io.safebyte.tlsinspector.probes

import burp.api.montoya.http.message.requests.HttpRequest
import io.safebyte.tlsinspector.ProbeContext
import io.safebyte.tlsinspector.TlsConfidence
import io.safebyte.tlsinspector.TlsScanResult
import io.safebyte.tlsinspector.TlsSeverity
import io.safebyte.tlsinspector.data.HstsPreloadList
import io.safebyte.tlsinspector.data.PreloadStatus
import io.safebyte.tlsinspector.reporting.TlsFinding

/**
 * HSTS Preload Probe — checks two things:
 *
 * 1. Live HSTS header check: sends an HTTPS GET to the target and inspects the
 *    Strict-Transport-Security header for presence, max-age, includeSubDomains, preload directives.
 *
 * 2. Bundled preload list check: consults the bundled hsts-preload.json to report whether
 *    the target domain is in the Chromium HSTS preload list.
 *
 * Note: The bundled preload list is a ~75-entry subset. NotInList results are inconclusive.
 * Full Chromium list (~150K entries) deferred to MS E.
 *
 * HSTS is defined in RFC 6797. The minimum recommended max-age is 6 months (15768000 seconds).
 * Mozilla Intermediate and PCI DSS 4.0 recommend a minimum of 1 year (31536000 seconds).
 */
class HstsPreloadProbe : TlsProbe {
    override val id = "HSTS_PRELOAD"
    override val displayName = "HSTS Header + Preload Check (RFC 6797)"
    override val kind = ProbeKind.INFORMATIONAL

    // 1 year in seconds — minimum recommended max-age
    private val MIN_MAXAGE_RECOMMENDED = 31_536_000L
    // 6 months — minimum required by most policies
    private val MIN_MAXAGE_MINIMUM = 15_768_000L

    override fun run(ctx: ProbeContext, result: TlsScanResult): List<TlsFinding> =
        runWithResult(ctx, result).findings

    override fun runWithResult(ctx: ProbeContext, result: TlsScanResult): ProbeResult {
        val started = System.currentTimeMillis()
        val elapsed = { System.currentTimeMillis() - started }

        val findings = mutableListOf<TlsFinding>()

        // 1. Live header check via Montoya HTTP API
        try {
            val req = HttpRequest.httpRequestFromUrl("https://${ctx.host}:${ctx.port}/")
            val resp = ctx.api.http().sendRequest(req)
            val hstsHeader = resp.response()?.headerValue("Strict-Transport-Security")

            if (hstsHeader == null) {
                val finding = TlsFinding(
                    id = "HSTS_PRELOAD:no_hsts_header",
                    title = "HSTS Header Missing (RFC 6797)",
                    severity = TlsSeverity.MEDIUM,
                    confidence = TlsConfidence.CERTAIN,
                    descriptionHtml = """
                        <p><b>Summary:</b> The server does not return an HTTP
                        <code>Strict-Transport-Security</code> header in its HTTPS response.
                        Without HSTS, browsers may downgrade HTTPS connections to HTTP
                        (SSL stripping attacks) and will not enforce secure connections on
                        subsequent visits.</p>
                        <p><b>Request URL:</b> <code>https://${ctx.host}:${ctx.port}/</code></p>
                        <p><b>HSTS header:</b> absent</p>
                        <p><b>Compliance impact:</b> Mozilla Intermediate recommendation.
                        PCI DSS 4.0 §4.2.1 (secure transmission of cardholder data).
                        ETSI TS 119 312 §6.3 (banking sector).</p>
                    """.trimIndent(),
                    remediationHtml = """
                        <p>Add the Strict-Transport-Security header to all HTTPS responses:</p>
                        <ul>
                        <li><b>Nginx:</b> <code>add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;</code></li>
                        <li><b>Apache:</b> <code>Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"</code></li>
                        </ul>
                        <p>Ensure <code>max-age</code> is at least 31536000 (1 year).
                        Use <code>preload</code> and submit to hstspreload.org for browser preloading.</p>
                    """.trimIndent(),
                    references = listOf(
                        "https://datatracker.ietf.org/doc/html/rfc6797",
                        "https://hstspreload.org/",
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/07-Testing_Strict_Transport_Security",
                    )
                )
                synchronized(result) { result.findings.add(finding) }
                findings.add(finding)
            } else {
                // Parse the HSTS header
                val hstsFindings = parseHstsHeader(ctx.host, hstsHeader, result)
                findings.addAll(hstsFindings)
            }
        } catch (e: Exception) {
            // HTTP request failure — skip live header check, continue with preload check
        }

        // 2. Bundled preload list check
        val preloadStatus = HstsPreloadList.check(ctx.host)
        when (preloadStatus) {
            is PreloadStatus.InList -> {
                val finding = TlsFinding(
                    id = "HSTS_PRELOAD:in_preload_list",
                    title = "Domain in HSTS Preload List: ${preloadStatus.matchedDomain}",
                    severity = TlsSeverity.INFO,
                    confidence = TlsConfidence.FIRM,
                    descriptionHtml = """
                        <p><b>Summary:</b> <code>${ctx.host}</code> (matched via
                        <code>${preloadStatus.matchedDomain}</code>) is in the Chromium HSTS
                        preload list (bundled subset). Browsers will enforce HTTPS connections
                        to this domain even before the first visit.</p>
                        <p><b>Include subdomains:</b> ${preloadStatus.includeSubdomains}</p>
                        <p><b>Note:</b> The bundled preload list is a ~${HstsPreloadList.size}-entry
                        subset. Full Chromium list (~150K entries) deferred to MS E.</p>
                    """.trimIndent(),
                    references = listOf(
                        "https://hstspreload.org/",
                        "https://chromium.googlesource.com/chromium/src/+/main/net/http/transport_security_state_static.json",
                    )
                )
                synchronized(result) { result.findings.add(finding) }
                findings.add(finding)
            }
            is PreloadStatus.NotInList -> {
                // Not in bundled subset — result is inconclusive (not a finding)
                // Full preload list check deferred to MS E
            }
        }

        return if (findings.isEmpty()) {
            ProbeResult.notVulnerable(id, displayName, elapsed())
                .copy(message = "HSTS header present and well-configured")
        } else {
            ProbeResult.informational(id, displayName, findings, elapsed())
        }
    }

    private fun parseHstsHeader(
        host: String,
        headerValue: String,
        result: TlsScanResult
    ): List<TlsFinding> {
        val findings = mutableListOf<TlsFinding>()
        val directives = headerValue.split(';').map { it.trim().lowercase() }

        val maxAge = directives.firstOrNull { it.startsWith("max-age=") }
            ?.removePrefix("max-age=")?.toLongOrNull() ?: 0L
        val hasIncludeSubdomains = directives.any { it == "includesubdomains" }
        val hasPreload = directives.any { it == "preload" }

        if (maxAge < MIN_MAXAGE_MINIMUM) {
            val finding = TlsFinding(
                id = "HSTS_PRELOAD:hsts_maxage_too_short",
                title = "HSTS max-age Too Short (< 6 months)",
                severity = TlsSeverity.LOW,
                confidence = TlsConfidence.CERTAIN,
                descriptionHtml = """
                    <p><b>Summary:</b> The <code>Strict-Transport-Security</code> header is present
                    but the <code>max-age</code> directive is too short (${maxAge}s, less than
                    the recommended minimum of ${MIN_MAXAGE_MINIMUM}s = 6 months).</p>
                    <p><b>Header value:</b> <code>$headerValue</code></p>
                    <p><b>Impact:</b> Short max-age reduces protection against SSL stripping attacks.
                    Each short-lived HSTS window creates an opportunity for downgrade attacks.</p>
                    <p><b>Compliance:</b> Mozilla Intermediate recommends min 6 months (15768000s).
                    PCI DSS 4.0 and ETSI TS 119 312 recommend 1 year (31536000s).</p>
                """.trimIndent(),
                remediationHtml = "<p>Increase <code>max-age</code> to at least 31536000 (1 year). " +
                    "Example: <code>Strict-Transport-Security: max-age=31536000; includeSubDomains; preload</code></p>",
                references = listOf(
                    "https://datatracker.ietf.org/doc/html/rfc6797#section-6.1.1",
                    "https://hstspreload.org/",
                )
            )
            synchronized(result) { result.findings.add(finding) }
            findings.add(finding)
        } else if (maxAge < MIN_MAXAGE_RECOMMENDED) {
            // max-age >= 6 months but < 1 year — note only (INFO)
            val finding = TlsFinding(
                id = "HSTS_PRELOAD:hsts_maxage_below_recommended",
                title = "HSTS max-age Below 1 Year (Recommended)",
                severity = TlsSeverity.INFO,
                confidence = TlsConfidence.CERTAIN,
                descriptionHtml = """
                    <p><b>Summary:</b> HSTS max-age is ${maxAge}s (${maxAge / 86400} days),
                    which meets the minimum but is below the 1-year recommendation
                    (31536000s) of Mozilla, PCI DSS 4.0, and hstspreload.org eligibility.</p>
                    <p><b>Header:</b> <code>$headerValue</code></p>
                """.trimIndent(),
                references = listOf("https://hstspreload.org/#requirements")
            )
            synchronized(result) { result.findings.add(finding) }
            findings.add(finding)
        }

        if (!hasIncludeSubdomains) {
            val finding = TlsFinding(
                id = "HSTS_PRELOAD:hsts_no_include_subdomains",
                title = "HSTS Missing includeSubDomains Directive",
                severity = TlsSeverity.LOW,
                confidence = TlsConfidence.CERTAIN,
                descriptionHtml = """
                    <p><b>Summary:</b> The HSTS header does not include the
                    <code>includeSubDomains</code> directive. Subdomains of <code>$host</code>
                    are not protected by HSTS — an attacker could downgrade connections to
                    a subdomain (e.g., <code>login.$host</code>) and perform cookie injection
                    attacks (RFC 6797 §14.4).</p>
                    <p><b>Header:</b> <code>$headerValue</code></p>
                """.trimIndent(),
                remediationHtml = "<p>Add <code>includeSubDomains</code> to the HSTS header if all " +
                    "subdomains support HTTPS. Example: " +
                    "<code>Strict-Transport-Security: max-age=31536000; includeSubDomains; preload</code></p>",
                references = listOf(
                    "https://datatracker.ietf.org/doc/html/rfc6797#section-6.1.2",
                )
            )
            synchronized(result) { result.findings.add(finding) }
            findings.add(finding)
        }

        if (!hasPreload) {
            // Informational only — preload is optional but best practice
            val finding = TlsFinding(
                id = "HSTS_PRELOAD:hsts_no_preload",
                title = "HSTS preload Directive Missing (Not Eligible for Preload List)",
                severity = TlsSeverity.INFO,
                confidence = TlsConfidence.CERTAIN,
                descriptionHtml = """
                    <p><b>Summary:</b> The HSTS header does not include the <code>preload</code>
                    directive. Without it, the domain cannot be submitted to the Chromium HSTS
                    preload list (hstspreload.org), which would protect users on their very first
                    visit before any HSTS header has been seen.</p>
                    <p><b>Header:</b> <code>$headerValue</code></p>
                    <p>This is an informational finding — preload is a best practice, not a
                    requirement in most compliance frameworks.</p>
                """.trimIndent(),
                references = listOf("https://hstspreload.org/#requirements")
            )
            synchronized(result) { result.findings.add(finding) }
            findings.add(finding)
        }

        return findings
    }
}
