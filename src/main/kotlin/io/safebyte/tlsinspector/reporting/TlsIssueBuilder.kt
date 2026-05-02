package io.safebyte.tlsinspector.reporting

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import io.safebyte.tlsinspector.TlsConfidence
import io.safebyte.tlsinspector.TlsSeverity

class TlsIssueBuilder(private val api: MontoyaApi) {

    fun reportToBurp(finding: TlsFinding, host: String, port: Int) {
        try {
            api.siteMap().add(build(finding, host, port))
        } catch (e: Exception) {
            api.logging().logToError("[TlsAudit] Failed to add issue '${finding.title}': ${e.message}")
        }
    }

    fun build(finding: TlsFinding, host: String, port: Int): AuditIssue {
        val baseUrl = "https://$host:$port/"
        val syntheticReq = HttpRequest.httpRequestFromUrl(baseUrl)
        val syntheticReqRes = HttpRequestResponse.httpRequestResponse(syntheticReq, null)

        // CRITICAL prefix since Burp's max severity is HIGH
        val titlePrefix = if (finding.severity == TlsSeverity.CRITICAL) "[CRITICAL] " else ""
        val name = "$titlePrefix${finding.title}"

        val refsHtml = if (finding.references.isNotEmpty())
            "<p><b>References:</b></p><ul>${finding.references.joinToString("") {
                "<li><a href=\"${escapeAttr(it)}\">${escapeHtml(it)}</a></li>"
            }}</ul>"
        else ""

        val detail = sanitizeHtml("""
            ${finding.descriptionHtml}
            $refsHtml
            <p><i>Detected by SafebyteAI TLS Audit Scanner — id=${escapeHtml(finding.id)}</i></p>
        """.trimIndent())

        val remediation = sanitizeHtml(
            finding.remediationHtml ?: "<p>See finding description for remediation guidance.</p>"
        )
        val background = sanitizeHtml(buildBackgroundHtml())
        val remediationBg = sanitizeHtml(buildRemediationBackgroundHtml())

        return AuditIssue.auditIssue(
            name,
            detail,
            remediation,
            baseUrl,
            mapSeverity(finding.severity),
            mapConfidence(finding.confidence),
            background,
            remediationBg,
            mapSeverity(finding.severity),
            syntheticReqRes,
        )
    }

    private fun buildBackgroundHtml(): String =
        "<p>This finding was produced by SafebyteAI's TLS Audit Scanner. " +
        "It evaluates the TLS configuration of the target endpoint against known cryptographic " +
        "vulnerabilities, certificate hygiene issues, and published compliance baselines " +
        "(Mozilla SSL Configuration, PCI DSS 4.0, NIST SP 800-52r2, ENISA / ETSI TS 119 312).</p>"

    private fun buildRemediationBackgroundHtml(): String =
        "<p>Remediation typically requires changes to the TLS server configuration " +
        "(cipher list, protocol versions, certificate parameters) or the X.509 certificate. " +
        "Refer to the linked specifications and the affected vendor's documentation for the " +
        "exact configuration directives.</p>"

    private fun mapSeverity(s: TlsSeverity): AuditIssueSeverity = when (s) {
        TlsSeverity.CRITICAL -> AuditIssueSeverity.HIGH
        TlsSeverity.HIGH     -> AuditIssueSeverity.HIGH
        TlsSeverity.MEDIUM   -> AuditIssueSeverity.MEDIUM
        TlsSeverity.LOW      -> AuditIssueSeverity.LOW
        TlsSeverity.INFO     -> AuditIssueSeverity.INFORMATION
    }

    private fun mapConfidence(c: TlsConfidence): AuditIssueConfidence = when (c) {
        TlsConfidence.CERTAIN   -> AuditIssueConfidence.CERTAIN
        TlsConfidence.FIRM      -> AuditIssueConfidence.FIRM
        TlsConfidence.TENTATIVE -> AuditIssueConfidence.TENTATIVE
    }

    /**
     * Whitelist-based HTML sanitiser. Allowed: p, b, i, em, strong, code, pre, ul, ol, li, br, a (href).
     * Anything else: tag dropped, content kept.
     */
    private fun sanitizeHtml(html: String): String {
        val allowedTags = setOf("p", "b", "i", "em", "strong", "code", "pre",
            "ul", "ol", "li", "br", "a")
        val tagRegex = Regex("</?\\s*([a-zA-Z][a-zA-Z0-9]*)([^>]*)>")
        val out = StringBuilder()
        var pos = 0
        for (match in tagRegex.findAll(html)) {
            out.append(html, pos, match.range.first)
            val tagName = match.groupValues[1].lowercase()
            val attrs = match.groupValues[2]
            val isClose = match.value.startsWith("</")
            if (tagName in allowedTags) {
                if (tagName == "a" && !isClose) {
                    val hrefMatch = Regex("""href\s*=\s*"([^"]*)"""").find(attrs)
                    if (hrefMatch != null) {
                        out.append("""<a href="${escapeAttr(hrefMatch.groupValues[1])}">""")
                    } else {
                        out.append("<a>")
                    }
                } else if (tagName == "a") {
                    out.append("</a>")
                } else {
                    if (isClose) out.append("</$tagName>") else out.append("<$tagName>")
                }
            }
            // forbidden tag → silently dropped, content preserved
            pos = match.range.last + 1
        }
        out.append(html, pos, html.length)
        return out.toString()
    }

    private fun escapeHtml(s: String): String =
        s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")

    private fun escapeAttr(s: String): String =
        s.replace("&", "&amp;").replace("\"", "&quot;").replace("<", "&lt;")
}
