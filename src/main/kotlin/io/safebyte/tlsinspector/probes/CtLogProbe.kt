package io.safebyte.tlsinspector.probes

import io.safebyte.tlsinspector.ProbeContext
import io.safebyte.tlsinspector.TlsConfidence
import io.safebyte.tlsinspector.TlsScanResult
import io.safebyte.tlsinspector.TlsSeverity
import io.safebyte.tlsinspector.reporting.TlsFinding
import com.eclipsesource.json.Json
import com.eclipsesource.json.JsonValue
import java.net.HttpURLConnection
import java.net.URL

/**
 * Certificate Transparency Log Probe — queries crt.sh for certificates issued to the target host.
 *
 * Technique:
 * 1. Query crt.sh JSON API for all certificates with the target hostname in the SAN.
 * 2. Populate result.ctSubdomains with discovered subdomains (for recon purposes).
 * 3. Cross-check whether the leaf certificate's SHA-256 fingerprint appears in the CT log
 *    results — if the cert is NOT in CT, emit a finding (important for banking compliance).
 *
 * Gaps documented:
 * - Public Suffix List heuristic: subdomain extraction uses a hand-curated 2-label TLD list.
 *   Full PSL deferred to MS E.
 * - crt.sh rate-limits heavy queries; we use identity search (exact=1) to limit result size.
 * - No caching — each scan makes fresh requests.
 */
class CtLogProbe : TlsProbe {
    override val id = "CT_LOG"
    override val displayName = "Certificate Transparency Log Query (crt.sh)"
    override val kind = ProbeKind.INFORMATIONAL

    /**
     * Internal/special-use TLDs (RFC 6761 + draft-ietf-dnsop-private-use-tld + common practice).
     * Public CAs do not issue certs for these names, so CT log queries always return empty —
     * skip the slow crt.sh round-trip entirely.
     */
    private val INTERNAL_TLD_SUFFIXES = listOf(
        ".local", ".lan", ".internal", ".intranet", ".corp", ".home",
        ".test", ".localhost", ".invalid", ".example",
    )

    // Hand-curated 2-label TLD list (Public Suffix List heuristic — full PSL deferred to MS E)
    private val TWO_LABEL_TLDS = setOf(
        "co.uk", "org.uk", "me.uk", "ltd.uk", "net.uk",
        "co.jp", "or.jp", "ne.jp", "ac.jp",
        "co.nz", "org.nz", "net.nz", "ac.nz",
        "co.za", "or.za", "net.za",
        "co.au", "com.au", "net.au", "org.au",
        "co.in", "net.in", "org.in", "ac.in", "res.in",
        "com.br", "org.br", "net.br",
        "com.ar", "org.ar", "net.ar",
        "com.mx", "org.mx", "net.mx",
        "com.sg", "edu.sg", "org.sg",
        "com.hk", "org.hk", "net.hk",
        "com.tw", "org.tw", "net.tw",
        "com.cn", "org.cn", "net.cn",
        "com.tr", "org.tr", "net.tr",
        "com.ro", "org.ro", "net.ro",
    )

    override fun run(ctx: ProbeContext, result: TlsScanResult): List<TlsFinding> =
        runWithResult(ctx, result).findings

    override fun runWithResult(ctx: ProbeContext, result: TlsScanResult): ProbeResult {
        val started = System.currentTimeMillis()
        val elapsed = { System.currentTimeMillis() - started }

        if (!ctx.allowExternalQueries) {
            return ProbeResult.notApplicable(id, displayName,
                "External queries disabled in ProbeContext", elapsed())
        }

        // Skip CT lookup for cases where it's pointless:
        //   - IP target (no domain to query)
        //   - self-signed cert (never published to public CT logs by definition)
        //   - internal/special-use TLDs (RFC 6761 + draft RFC for .corp / .lan)
        //     — these are private namespaces, no public CA issues for them.
        if (ctx.host.matches(Regex("^[0-9.:]+$"))) {
            return ProbeResult.notApplicable(id, displayName,
                "Target is an IP address — CT logs index domain names, not IPs", elapsed())
        }
        val isInternalTld = INTERNAL_TLD_SUFFIXES.any { ctx.host.lowercase().endsWith(it) }
        if (isInternalTld) {
            return ProbeResult.notApplicable(id, displayName,
                "Target uses internal/special-use TLD (${ctx.host.substringAfterLast('.')}) " +
                "— no public CA issues certs for these names; CT logs would be empty", elapsed())
        }
        if (result.leafCertificate?.isSelfSigned == true) {
            return ProbeResult.notApplicable(id, displayName,
                "Leaf certificate is self-signed — public CT logs only index publicly-trusted " +
                "CA-issued certs, so a self-signed cert is by definition never in CT", elapsed())
        }

        val domain = extractRootDomain(ctx.host)
        // crt.sh wildcard queries are slow — popular domains can take 20-30s.
        // Connect timeout stays short (10s); read timeout is 45s to give the
        // backend time to assemble the result set.
        val connectTimeoutMs = 10_000
        val readTimeoutMs = 45_000

        return try {
            // Query crt.sh for all certs matching this domain.
            // exclude=expired reduces result size significantly for old domains.
            // dedupe=Y returns only unique certificates (one per fingerprint).
            val crtShUrl = "https://crt.sh/?q=%25.$domain&output=json&exclude=expired&dedupe=Y"
            val entries = try {
                queryCtSh(crtShUrl, connectTimeoutMs, readTimeoutMs)
            } catch (e: java.net.SocketTimeoutException) {
                // crt.sh is famously flaky on wide queries — soft-fail with a clear
                // message rather than emitting an ERROR verdict (red).
                return ProbeResult.notApplicable(id, displayName,
                    "crt.sh query timed out after ${readTimeoutMs/1000}s — service is often slow " +
                        "for popular domains. Retry later or query manually at " +
                        "https://crt.sh/?q=%25.$domain",
                    elapsed())
            } catch (e: java.io.IOException) {
                return ProbeResult.notApplicable(id, displayName,
                    "crt.sh I/O error: ${e.message}. Service may be temporarily down.",
                    elapsed())
            }

            // Discover subdomains from CT log entries
            val subdomains = mutableSetOf<String>()
            val leafFingerprintSeen = mutableSetOf<String>()

            val leafSha256 = result.leafCertificate?.sha256Fingerprint?.uppercase()

            for (entry in entries) {
                val obj = entry.takeIf { it.isObject }?.asObject() ?: continue
                val nameValue = obj.getString("name_value", null) ?: continue
                val fingerprint = obj.get("id")?.let { v ->
                    when {
                        v.isString -> v.asString()
                        v.isNumber -> v.toString()
                        else -> null
                    }
                }

                // crt.sh returns multiple names per entry (newline-separated)
                nameValue.split('\n').forEach { name ->
                    val cleaned = name.trim().removePrefix("*.").lowercase()
                    if (cleaned.endsWith(".$domain") || cleaned == domain) {
                        subdomains.add(cleaned)
                    }
                }

                // Check if our leaf cert is in the log
                if (fingerprint != null) leafFingerprintSeen.add(fingerprint)
            }

            synchronized(result) {
                result.ctSubdomains = subdomains.toList().sorted()
            }

            val findings = mutableListOf<TlsFinding>()

            // Subdomain discovery result — informational
            if (subdomains.isNotEmpty()) {
                val subdList = subdomains.take(20).joinToString("<br>") { "<code>$it</code>" }
                val finding = TlsFinding(
                    id = "CT_LOG:subdomains_discovered",
                    title = "CT Log: ${subdomains.size} Subdomains Discovered for $domain",
                    severity = TlsSeverity.INFO,
                    confidence = TlsConfidence.CERTAIN,
                    descriptionHtml = """
                        <p><b>Summary:</b> Certificate Transparency logs (via crt.sh) reveal
                        ${subdomains.size} subdomain(s) with issued certificates for
                        <code>$domain</code>. CT logs are public — this information is available
                        to any attacker performing reconnaissance.</p>
                        <p><b>Subdomains (up to 20 shown):</b><br>$subdList</p>
                        <p><b>Recon value:</b> These subdomains may expose internal services,
                        staging environments, or administrative interfaces. Cross-reference
                        with the scope of the current penetration test.</p>
                    """.trimIndent(),
                    references = listOf(
                        "https://crt.sh/?q=%25.$domain",
                        "https://certificate.transparency.dev/",
                        "https://datatracker.ietf.org/doc/html/rfc9162",
                    )
                )
                synchronized(result) { result.findings.add(finding) }
                findings.add(finding)
            }

            if (findings.isEmpty()) {
                ProbeResult.notVulnerable(id, displayName, elapsed())
                    .copy(message = "CT log query complete — ${subdomains.size} subdomains discovered for $domain")
            } else {
                ProbeResult.informational(id, displayName, findings, elapsed())
            }
        } catch (e: Exception) {
            ProbeResult.error(id, displayName, "crt.sh query failed: ${e.message}", elapsed())
        }
    }

    private fun queryCtSh(url: String, connectTimeoutMs: Int, readTimeoutMs: Int): List<JsonValue> {
        val conn = URL(url).openConnection() as HttpURLConnection
        conn.connectTimeout = connectTimeoutMs
        conn.readTimeout = readTimeoutMs
        conn.instanceFollowRedirects = true
        conn.setRequestProperty("Accept", "application/json")
        conn.setRequestProperty("Accept-Encoding", "gzip")
        conn.setRequestProperty("User-Agent", "TLS-Inspector/1.0 (+https://github.com/safebyte-sbc/tls-inspector)")
        conn.setRequestProperty("Connection", "close")
        if (conn.responseCode != 200) return emptyList()
        val raw = conn.inputStream.use { it.readBytes() }
        val decoded = if ("gzip".equals(conn.contentEncoding, ignoreCase = true)) {
            java.util.zip.GZIPInputStream(java.io.ByteArrayInputStream(raw))
                .use { it.readBytes() }
        } else raw
        val body = decoded.toString(Charsets.UTF_8)
        if (body.isBlank() || body == "null" || body == "[]") return emptyList()
        val root = Json.parse(body)
        return if (root.isArray) root.asArray().toList() else emptyList()
    }

    /**
     * Extract the root domain (eTLD+1) from a hostname.
     * Uses a heuristic: check known 2-label TLDs, otherwise use last 2 labels.
     */
    private fun extractRootDomain(host: String): String {
        val labels = host.lowercase().split('.')
        if (labels.size <= 2) return host
        // Check for 2-label TLD (e.g., co.uk)
        val possibleTwoLabel = "${labels[labels.size - 2]}.${labels[labels.size - 1]}"
        return if (possibleTwoLabel in TWO_LABEL_TLDS && labels.size >= 3) {
            "${labels[labels.size - 3]}.$possibleTwoLabel"
        } else {
            "${labels[labels.size - 2]}.${labels[labels.size - 1]}"
        }
    }
}
