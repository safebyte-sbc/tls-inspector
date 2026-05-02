package io.safebyte.tlsinspector.ui

import io.safebyte.tlsinspector.CipherFlag
import io.safebyte.tlsinspector.CipherGrade
import io.safebyte.tlsinspector.CipherSuiteResult
import io.safebyte.tlsinspector.ProtocolStatus
import io.safebyte.tlsinspector.TlsProtocol
import io.safebyte.tlsinspector.TlsScanResult
import io.safebyte.tlsinspector.TlsSeverity
import io.safebyte.tlsinspector.probes.ProbeResult
import io.safebyte.tlsinspector.probes.Verdict
import io.safebyte.tlsinspector.reporting.TlsFinding
import io.safebyte.tlsinspector.reporting.TlsIssueBuilder
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import javax.swing.JComponent
import javax.swing.JEditorPane
import javax.swing.JScrollPane
import javax.swing.SwingUtilities
import javax.swing.event.HyperlinkEvent

/**
 * Single HTML panel replacing both TlsProgressPanel and TlsResultsTreePanel.
 *
 * Renders a JEditorPane with embedded CSS for:
 * - Real-time probe progress (pending → colored verdict) as scan runs
 * - Final full result: protocols, cipher suites, certificate, findings
 *
 * All UI mutations are dispatched via SwingUtilities.invokeLater.
 */
class TlsResultsHtmlPanel(private val issueBuilder: TlsIssueBuilder) {

    private val CSS = """
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            font-size: 11px; color: #333; padding: 10px; margin: 0;
        }
        h2 {
            color: #1a5f2a; border-bottom: 2px solid #2d8a4e;
            padding-bottom: 4px; margin-top: 16px; font-size: 13px;
        }
        h3 { color: #555; margin-top: 12px; font-size: 11px; margin-bottom: 4px; }
        .target {
            background: #f0f7f0; padding: 8px 12px; border-radius: 4px;
            border-left: 4px solid #2d8a4e; margin-bottom: 12px;
            font-family: 'Consolas', monospace; font-size: 11px;
        }
        .probe { padding: 4px 8px; margin: 2px 0; border-radius: 3px; display: block; font-size: 11px; }
        .probe-pending  { background: #f5f5f5; color: #999; }
        .probe-vulnerable   { background: #ffebee; color: #c62828; border-left: 4px solid #c62828; }
        .probe-potentially  { background: #fff8e1; color: #ef6c00; border-left: 4px solid #ef6c00; }
        .probe-safe  { background: #e8f5e9; color: #2e7d32; border-left: 4px solid #2e7d32; }
        .probe-na    { background: #f5f5f5; color: #757575; border-left: 4px solid #bbb; }
        .probe-error { background: #fce4ec; color: #ad1457; border-left: 4px solid #ad1457; }
        .icon-vulnerable  { color: #c62828; font-size: 14px; font-weight: bold; }
        .icon-potentially { color: #ef6c00; font-size: 14px; font-weight: bold; }
        .icon-safe        { color: #2e7d32; font-size: 14px; font-weight: bold; }
        .icon-na          { color: #9e9e9e; font-size: 13px; }
        .icon-error       { color: #ad1457; font-size: 14px; font-weight: bold; }
        .icon-info        { color: #1976d2; font-size: 13px; font-weight: bold; }
        .duration { color: #999; font-size: 10px; float: right; }
        .severity-critical { color: #b71c1c; font-weight: bold; }
        .severity-high     { color: #c62828; font-weight: bold; }
        .severity-medium   { color: #ef6c00; font-weight: bold; }
        .severity-low      { color: #f9a825; font-weight: bold; }
        .severity-info     { color: #1976d2; font-weight: bold; }
        .finding { padding: 6px 10px; margin: 4px 0; border-radius: 3px; border-left: 4px solid; font-size: 11px; }
        .finding-critical { background: #ffebee; border-color: #b71c1c; }
        .finding-high     { background: #ffebee; border-color: #c62828; }
        .finding-medium   { background: #fff8e1; border-color: #ef6c00; }
        .finding-low      { background: #fffde7; border-color: #fbc02d; }
        .finding-info     { background: #e3f2fd; border-color: #1976d2; }
        .refs { font-size: 11px; color: #555; margin-top: 4px; }
        .refs a { color: #1976d2; }
        code {
            background: #eee; padding: 1px 4px; border-radius: 2px;
            font-family: 'Consolas', monospace; font-size: 10px;
        }
        .proto-section { margin: 6px 0; }
        .proto-section .label { color: #555; font-weight: bold; margin-right: 6px; font-size: 11px; }
        .proto-chip {
            display: inline-block; padding: 3px 10px; border-radius: 10px;
            margin: 2px 3px; font-size: 11px; font-weight: bold;
        }
        .proto-modern     { background: #c8e6c9; color: #1b5e20; border: 1px solid #2e7d32; }
        .proto-deprecated { background: #ffccbc; color: #bf360c; border: 1px solid #bf360c; }
        .proto-disabled   { background: #f5f5f5; color: #9e9e9e; border: 1px solid #d0d0d0; }
        .proto-error      { background: #fce4ec; color: #880e4f; border: 1px solid #880e4f; }
        /* Inline icons for Protocols + Certificate sections — same color scheme as probe verdicts */
        .ico-warn { color: #ef6c00; font-size: 13px; font-weight: bold; }
        .ico-bad  { color: #c62828; font-size: 13px; font-weight: bold; }
        .ico-good { color: #2e7d32; font-size: 13px; font-weight: bold; }
        /* Findings separator — gray hr between cards */
        hr.finding-sep { border: 0; border-top: 1px solid #ddd; margin: 10px 0; }
        .cipher-row { padding: 2px 6px; margin: 1px 0; border-radius: 2px; font-size: 11px; }
        .cipher-strong     { background: #e8f5e9; color: #1b5e20; }
        .cipher-acceptable { background: #f1f8e9; color: #33691e; }
        .cipher-weak       { background: #fff8e1; color: #e65100; }
        .cipher-insecure   { background: #ffebee; color: #b71c1c; }
        .cert-table { border-collapse: collapse; width: 100%; margin-top: 4px; font-size: 11px; }
        .cert-table td { padding: 3px 8px; border-bottom: 1px solid #eee; vertical-align: top; }
        .cert-table td:first-child { color: #555; font-weight: bold; width: 140px; white-space: nowrap; }
        .cert-bad  { color: #c62828; font-weight: bold; }
        .cert-warn { color: #ef6c00; font-weight: bold; }
        .empty-state { color: #999; font-style: italic; padding: 16px; text-align: center; font-size: 11px; }
    """.trimIndent()

    private val editorPane = JEditorPane().apply {
        contentType = "text/html"
        isEditable = false
        putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, true)
        addHyperlinkListener { e ->
            if (e.eventType == HyperlinkEvent.EventType.ACTIVATED && e.url != null) {
                try { java.awt.Desktop.getDesktop().browse(e.url.toURI()) } catch (_: Exception) { }
            }
        }
    }

    /** JScrollPane wrapping the JEditorPane — add this to TlsAuditTab CENTER. */
    val component: JComponent = JScrollPane(editorPane)

    // Internal state for incremental probe rendering
    private val probeOrder = mutableListOf<String>()          // maintains insertion order
    private val probeNames = mutableMapOf<String, String>()   // id → displayName
    private val probeResults = mutableMapOf<String, ProbeResult?>() // id → result (null = pending)

    private var scanHeader: String = ""

    companion object {
        private val DATE_FMT: DateTimeFormatter =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneOffset.UTC)
        private const val MAX_CIPHERS_SHOWN = 100
    }

    // ── Public API ─────────────────────────────────────────────────────────────

    /** Return the current HTML content (full document). Used by the Save button. */
    fun getHtml(): String = editorPane.text ?: ""

    /** Reset to empty / welcome state. */
    fun reset() {
        SwingUtilities.invokeLater {
            probeOrder.clear()
            probeNames.clear()
            probeResults.clear()
            scanHeader = ""
            editorPane.text = "<html><body style='font-family:sans-serif;font-size:12px;color:#999;padding:16px'>" +
                "<i>No scan result. Enter a host above and click Run Scan.</i></body></html>"
        }
    }

    /** Called at scan start to set the header block. */
    fun setHeader(host: String, port: Int, profile: String) {
        scanHeader = """<div class="target">
            <b>Target:</b> $host:$port &nbsp;&nbsp; <b>Profile:</b> $profile<br>
            <b>Started:</b> ${DATE_FMT.format(java.time.Instant.now())} UTC
        </div>"""
    }

    /**
     * Register all probes upfront (before they run).
     * Renders them all as "Pending" immediately so the user sees the full list.
     */
    fun registerProbes(probes: List<Pair<String, String>>) {
        SwingUtilities.invokeLater {
            probeOrder.clear()
            probeNames.clear()
            probeResults.clear()
            for ((id, name) in probes) {
                probeOrder.add(id)
                probeNames[id] = name
                probeResults[id] = null
            }
            renderProbeView()
        }
    }

    /**
     * Update a single probe's result (called as each probe completes on background thread).
     * Must be thread-safe — dispatches to EDT internally.
     */
    fun updateProbe(probeResult: ProbeResult) {
        SwingUtilities.invokeLater {
            probeResults[probeResult.probeId] = probeResult
            renderProbeView()
        }
    }

    /**
     * Render the full final result with all sections.
     * Called at scan end on the background polling thread — dispatches to EDT.
     */
    fun renderFinalResult(result: TlsScanResult, host: String, port: Int) {
        SwingUtilities.invokeLater {
            editorPane.text = buildFinalHtml(result, host, port)
            editorPane.caretPosition = 0
        }
    }

    // ── Private rendering helpers ───────────────────────────────────────────────

    private fun renderProbeView() {
        val sb = StringBuilder()
        sb.append("<html><head><style>$CSS</style></head><body>")
        sb.append(scanHeader)

        val total = probeOrder.size
        val done = probeResults.values.count { it != null }
        sb.append("<h2>Vulnerability Probes ($done / $total)</h2>")

        for (id in probeOrder) {
            val pr = probeResults[id]
            val name = probeNames[id] ?: id
            if (pr == null) {
                sb.append("""<div class="probe probe-pending">&#x231B; $name &mdash; Pending&hellip;</div>""")
            } else {
                val (cssClass, icon, verdictText) = verdictStyle(pr)
                val msg = if (pr.message != null) ": ${escHtml(pr.message)}" else ""
                sb.append("""<div class="probe $cssClass">""")
                sb.append("""$icon ${escHtml(name)} &mdash; $verdictText$msg""")
                sb.append("""<span class="duration">${pr.durationMs} ms</span>""")
                sb.append("</div>")
            }
        }

        sb.append("</body></html>")
        editorPane.text = sb.toString()
        editorPane.caretPosition = 0
    }

    private fun buildFinalHtml(result: TlsScanResult, host: String, port: Int): String {
        val sb = StringBuilder()
        sb.append("<html><head><style>$CSS</style></head><body>")

        // Header block
        val startedStr = DATE_FMT.format(result.startedAt)
        val finishedStr = result.finishedAt?.let { DATE_FMT.format(it) } ?: "—"
        sb.append("""<div class="target">""")
        sb.append("""<b>Target:</b> $host:$port &nbsp;&nbsp; <b>Scan:</b> ${result.target}<br>""")
        sb.append("""<b>Started:</b> $startedStr UTC &nbsp;&nbsp; <b>Finished:</b> $finishedStr UTC""")
        sb.append("</div>")

        // Protocols
        appendProtocolsSection(sb, result)

        // Cipher Suites
        appendCiphersSection(sb, result)

        // Certificate
        appendCertSection(sb, result)

        // Vulnerability Probes (full list at end)
        appendProbesSection(sb, result)

        // Findings
        appendFindingsSection(sb, result, host, port)

        sb.append("</body></html>")
        return sb.toString()
    }

    private fun appendProtocolsSection(sb: StringBuilder, result: TlsScanResult) {
        val all = TlsProtocol.values().toList()
        val offered = all.filter { result.protocolsOffered[it] == ProtocolStatus.OFFERED }
        val errored = all.filter { result.protocolsOffered[it] == ProtocolStatus.ERROR }
        val disabled = all - offered.toSet() - errored.toSet()

        sb.append("<h2>Protocols (${offered.size} offered)</h2>")

        // Offered group
        sb.append("""<div class="proto-section"><span class="label">Offered:</span>""")
        if (offered.isEmpty()) {
            sb.append("""<span style="color:#999; font-style:italic">none</span>""")
        } else {
            for (proto in offered) {
                val chipClass = if (proto.isDeprecated) "proto-deprecated" else "proto-modern"
                val icon = if (proto.isDeprecated)
                    "<span class='ico-warn'>&#x26A0;</span>"
                else
                    "<span class='ico-good'>&#x2713;</span>"
                sb.append("""<span class="proto-chip $chipClass">$icon ${escHtml(proto.displayName)}</span>""")
            }
        }
        sb.append("</div>")

        // Disabled group — chips separated visually by extra whitespace
        sb.append("""<div class="proto-section"><span class="label">Disabled:</span>""")
        if (disabled.isEmpty()) {
            sb.append("""<span style="color:#999; font-style:italic">none</span>""")
        } else {
            sb.append(disabled.joinToString(" &nbsp;|&nbsp; ") { proto ->
                """<span class="proto-chip proto-disabled">${escHtml(proto.displayName)}</span>"""
            })
        }
        sb.append("</div>")

        // Error group (only if any)
        if (errored.isNotEmpty()) {
            sb.append("""<div class="proto-section"><span class="label">Probe error:</span>""")
            for (proto in errored) {
                sb.append("""<span class="proto-chip proto-error"><span class='ico-bad'>&#x2717;</span> ${escHtml(proto.displayName)}</span>""")
            }
            sb.append("</div>")
        }
    }

    private fun appendCiphersSection(sb: StringBuilder, result: TlsScanResult) {
        val totalCiphers = result.ciphersByProtocol.values.sumOf { it.size }
        if (totalCiphers == 0) return

        sb.append("<h2>Cipher Suites ($totalCiphers total)</h2>")

        for (proto in TlsProtocol.values()) {
            val ciphers = result.ciphersByProtocol[proto] ?: continue
            if (ciphers.isEmpty()) continue

            sb.append("<h3>${escHtml(proto.displayName)} (${ciphers.size} suites)</h3>")

            val displayed = ciphers.take(MAX_CIPHERS_SHOWN)
            for (cipher in displayed) {
                val rowClass = when (cipher.grade) {
                    CipherGrade.STRONG -> "cipher-strong"
                    CipherGrade.ACCEPTABLE -> "cipher-acceptable"
                    CipherGrade.WEAK -> "cipher-weak"
                    CipherGrade.INSECURE -> "cipher-insecure"
                }
                val icon = when (cipher.grade) {
                    CipherGrade.STRONG, CipherGrade.ACCEPTABLE -> "✓"
                    else -> "⚠"
                }
                val flags = buildCipherFlagsHtml(cipher)
                sb.append("""<div class="cipher-row $rowClass">$icon ${escHtml(cipher.name)} (${cipher.grade.name})$flags</div>""")
            }
            val remaining = ciphers.size - displayed.size
            if (remaining > 0) {
                sb.append("""<div class="cipher-row">&hellip; ($remaining more)</div>""")
            }
        }
    }

    private fun buildCipherFlagsHtml(cipher: CipherSuiteResult): String {
        val flagLabels = mutableListOf<String>()
        if (CipherFlag.RC4 in cipher.flags) flagLabels.add("RC4")
        if (CipherFlag.TRIPLE_DES_64BIT_BLOCK in cipher.flags) flagLabels.add("3DES")
        if (CipherFlag.EXPORT_GRADE in cipher.flags) flagLabels.add("EXPORT")
        if (CipherFlag.NULL_CIPHER in cipher.flags) flagLabels.add("NULL")
        if (CipherFlag.ANON_KX in cipher.flags) flagLabels.add("ANON")
        if (CipherFlag.FORWARD_SECRECY in cipher.flags) flagLabels.add("FS")
        if (CipherFlag.AEAD in cipher.flags) flagLabels.add("AEAD")
        if (CipherFlag.POST_QUANTUM_HYBRID in cipher.flags) flagLabels.add("PQC")
        if (flagLabels.isEmpty()) return ""
        return " &nbsp; <code>${flagLabels.joinToString(", ")}</code>"
    }

    private fun appendCertSection(sb: StringBuilder, result: TlsScanResult) {
        sb.append("<h2>Certificate</h2>")
        val cert = result.leafCertificate
        if (cert == null) {
            sb.append("""<p style="color:#999"><i>(no certificate retrieved)</i></p>""")
            return
        }

        sb.append("""<table class="cert-table">""")

        val subject = cert.subjectDn.commonName ?: cert.subjectDn.raw
        sb.append("<tr><td>Subject</td><td>${escHtml(subject)}</td></tr>")

        val issuer = cert.issuerDn.commonName ?: cert.issuerDn.raw
        sb.append("<tr><td>Issuer</td><td>${escHtml(issuer)}</td></tr>")

        val notBefore = DATE_FMT.format(cert.notBefore)
        val notAfter = DATE_FMT.format(cert.notAfter)
        val validityLabel = when {
            cert.isExpired -> "<span class='cert-bad'><span class='ico-bad'>&#x26A0;</span> ${cert.daysToExpiry} days (EXPIRED)</span>"
            cert.isNotYetValid -> "<span class='cert-warn'><span class='ico-warn'>&#x26A0;</span> not yet valid</span>"
            cert.daysToExpiry < 30 -> "<span class='cert-warn'><span class='ico-warn'>&#x26A0;</span> ${cert.daysToExpiry} days remaining (expiring soon)</span>"
            else -> "${cert.daysToExpiry} days remaining"
        }
        sb.append("<tr><td>Validity</td><td>${escHtml(notBefore)} &rarr; ${escHtml(notAfter)} ($validityLabel)</td></tr>")

        // Public key — flag weak RSA / EC sizes in red
        val keyStr = "${cert.publicKey.algorithm} ${cert.publicKey.sizeBits} bits"
        val keyCurve = cert.publicKey.curveName?.let { " ($it)" } ?: ""
        val isKeyWeak = (cert.publicKey.algorithm == "RSA" && cert.publicKey.sizeBits < 2048) ||
            (cert.publicKey.algorithm == "EC" && cert.publicKey.sizeBits < 256)
        val keyHtml = if (isKeyWeak)
            "<span class='cert-bad'><span class='ico-bad'>&#x26A0;</span> ${escHtml(keyStr + keyCurve)} (weak)</span>"
        else
            escHtml(keyStr + keyCurve)
        sb.append("<tr><td>Public Key</td><td>$keyHtml</td></tr>")

        // Signature — flag SHA-1 / MD5 in red
        val sigAlg = cert.signatureAlgorithm
        val isSigWeak = sigAlg.hashAlgorithm in setOf("SHA-1", "MD5")
        val sigHtml = if (isSigWeak)
            "<span class='cert-bad'><span class='ico-bad'>&#x26A0;</span> ${escHtml(sigAlg.name)} (weak hash: ${escHtml(sigAlg.hashAlgorithm)})</span>"
        else
            escHtml(sigAlg.name)
        sb.append("<tr><td>Signature</td><td>$sigHtml</td></tr>")

        if (cert.subjectAlternativeNames.isNotEmpty()) {
            val sans = cert.subjectAlternativeNames.take(20).joinToString(", ") { it.value }
            val more = if (cert.subjectAlternativeNames.size > 20) " + ${cert.subjectAlternativeNames.size - 20} more" else ""
            sb.append("<tr><td>SANs</td><td>${escHtml(sans + more)}</td></tr>")
        }

        // Self-signed — RED if Yes (it's a vulnerability for public sites)
        val selfSignedHtml = if (cert.isSelfSigned)
            "<span class='cert-bad'><span class='ico-bad'>&#x26A0;</span> Yes</span>"
        else
            "No"
        sb.append("<tr><td>Self-signed</td><td>$selfSignedHtml</td></tr>")

        sb.append("<tr><td>SHA-256</td><td><code>${escHtml(cert.sha256Fingerprint)}</code></td></tr>")

        if (cert.unknownCriticalExtensions.isNotEmpty()) {
            sb.append("<tr><td>Unknown Critical Ext</td><td><span class='cert-bad'><span class='ico-bad'>&#x26A0;</span> ${cert.unknownCriticalExtensions.joinToString(", ")}</span></td></tr>")
        }

        sb.append("</table>")
    }

    private fun appendProbesSection(sb: StringBuilder, result: TlsScanResult) {
        val vulnProbes = result.probeResults.filter { pr ->
            pr.probeId !in setOf("PROTOCOL_ENUM", "CIPHER_ENUM", "CERT_VALIDATION")
        }
        if (vulnProbes.isEmpty()) return

        sb.append("<h2>Vulnerability Probes (${vulnProbes.size})</h2>")

        for (pr in vulnProbes) {
            val (cssClass, icon, verdictText) = verdictStyle(pr)
            val msg = if (pr.message != null) ": ${escHtml(pr.message)}" else ""
            sb.append("""<div class="probe $cssClass">""")
            sb.append("""$icon ${escHtml(pr.displayName)} &mdash; $verdictText$msg""")
            sb.append("""<span class="duration">${pr.durationMs} ms</span>""")
            sb.append("</div>")
        }
    }

    private fun appendFindingsSection(sb: StringBuilder, result: TlsScanResult, host: String, port: Int) {
        val sorted = result.findings.sortedWith(compareBy {
            when (it.severity) {
                TlsSeverity.CRITICAL -> 0; TlsSeverity.HIGH -> 1
                TlsSeverity.MEDIUM -> 2; TlsSeverity.LOW -> 3; TlsSeverity.INFO -> 4
            }
        })

        sb.append("<h2>Findings (${sorted.size})</h2>")

        if (sorted.isEmpty()) {
            sb.append("""<div class="empty-state">No findings — target passed all checks.</div>""")
            return
        }

        for ((index, finding) in sorted.withIndex()) {
            appendFindingCard(sb, finding)
            // Gray separator between cards (not after the last one)
            if (index < sorted.size - 1) {
                sb.append("""<hr class="finding-sep">""")
            }
        }
    }

    private fun appendFindingCard(sb: StringBuilder, finding: TlsFinding) {
        val (divClass, severityClass, severityLabel) = findingStyle(finding.severity)
        sb.append("""<div class="finding $divClass">""")
        sb.append("""<span class="$severityClass">$severityLabel</span> &nbsp; <b>${escHtml(finding.title)}</b><br>""")
        // descriptionHtml is already sanitized HTML from our own probes
        sb.append(finding.descriptionHtml)
        if (finding.remediationHtml != null) {
            sb.append("<br><b>Remediation:</b> ")
            sb.append(finding.remediationHtml)
        }
        if (finding.references.isNotEmpty()) {
            sb.append("""<div class="refs"><b>References:</b> """)
            sb.append(finding.references.joinToString(" &nbsp;|&nbsp; ") { url ->
                """<a href="$url">${escHtml(url)}</a>"""
            })
            sb.append("</div>")
        }
        sb.append("</div>")
    }

    // ── Verdict → CSS/icon/text triple ─────────────────────────────────────────

    private data class VerdictStyle(val cssClass: String, val icon: String, val text: String)

    /**
     * Color-coded icons via inline span with class so JEditorPane renders them tinted.
     * Uses Unicode warning triangle (⚠ U+26A0), check (✓ U+2713), cross (✗ U+2717),
     * info (ℹ U+2139) — coloured via .icon-* CSS classes. JEditorPane HTML 3.2
     * renderer doesn't render colour emoji glyphs, so we tint Unicode symbols.
     */
    private fun verdictStyle(pr: ProbeResult): VerdictStyle = when (pr.verdict) {
        Verdict.VULNERABLE ->
            VerdictStyle("probe-vulnerable",
                "<span class='icon-vulnerable'>&#x26A0;</span>", "VULNERABLE")
        Verdict.POTENTIALLY_VULNERABLE ->
            VerdictStyle("probe-potentially",
                "<span class='icon-potentially'>&#x26A0;</span>", "Potentially vulnerable")
        Verdict.NOT_VULNERABLE ->
            VerdictStyle("probe-safe",
                "<span class='icon-safe'>&#x2713;</span>", "Not vulnerable")
        Verdict.NOT_APPLICABLE ->
            VerdictStyle("probe-na",
                "<span class='icon-na'>&middot;</span>", "Not applicable")
        Verdict.UNDETERMINED -> when (pr.status) {
            ProbeResult.Status.ERROR ->
                VerdictStyle("probe-error",
                    "<span class='icon-error'>&#x2717;</span>", "Error")
            ProbeResult.Status.TIMEOUT ->
                VerdictStyle("probe-potentially",
                    "<span class='icon-potentially'>&#x23F1;</span>", "Timeout")
            ProbeResult.Status.SUCCESS ->
                VerdictStyle("probe-safe",
                    "<span class='icon-info'>&#x2139;</span>", "Informational")
            else ->
                VerdictStyle("probe-na",
                    "<span class='icon-na'>&middot;</span>", "N/A")
        }
    }

    // ── Finding severity → CSS class triple ────────────────────────────────────

    private data class FindingStyle(val divClass: String, val spanClass: String, val label: String)

    private fun findingStyle(severity: TlsSeverity): FindingStyle = when (severity) {
        TlsSeverity.CRITICAL -> FindingStyle("finding-critical", "severity-critical", "CRITICAL")
        TlsSeverity.HIGH     -> FindingStyle("finding-high",     "severity-high",     "HIGH")
        TlsSeverity.MEDIUM   -> FindingStyle("finding-medium",   "severity-medium",   "MEDIUM")
        TlsSeverity.LOW      -> FindingStyle("finding-low",      "severity-low",      "LOW")
        TlsSeverity.INFO     -> FindingStyle("finding-info",     "severity-info",     "INFO")
    }

    // ── HTML escaping ───────────────────────────────────────────────────────────

    private fun escHtml(s: String): String = s
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
}
