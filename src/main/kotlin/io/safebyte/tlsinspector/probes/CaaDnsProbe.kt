package io.safebyte.tlsinspector.probes

import io.safebyte.tlsinspector.ProbeContext
import io.safebyte.tlsinspector.TlsConfidence
import io.safebyte.tlsinspector.TlsScanResult
import io.safebyte.tlsinspector.TlsSeverity
import io.safebyte.tlsinspector.reporting.TlsFinding
import org.xbill.DNS.Lookup
import org.xbill.DNS.Record

/**
 * CAA DNS Probe — checks whether the domain has CAA records (RFC 8659) restricting
 * which Certificate Authorities may issue certificates for it.
 *
 * This probe REPORTS what it finds — it does NOT cross-validate CAA records against
 * the served certificate's issuer because:
 *   - CAA validation is the CA's responsibility at issuance time (CA/B Forum BR §3.2.2.8),
 *     not a client-side check at connection time.
 *   - There is no standardized mapping between CAA values (e.g. `digicert.com`) and
 *     certificate issuer DN organization fields (e.g. `DigiCert Inc`). Naive string
 *     comparison produces false positives — they're the same entity but not the same string.
 *
 * Verdicts:
 *   - CAA absent (no records on host or any parent zone) → POTENTIALLY_VULNERABLE,
 *     LOW finding `CAA_NO_RECORDS` — defense-in-depth gap.
 *   - CAA present with restrictive records → NOT_VULNERABLE, INFORMATION finding
 *     `CAA_RECORDS_PRESENT` — informational only, never red.
 *   - CAA present with `issue ";"` (forbids all) → NOT_VULNERABLE, INFORMATION finding
 *     `CAA_NO_ISSUE_ALLOWED`.
 *
 * Missing `iodef` tag is mentioned as a best-practice recommendation, NOT as a vulnerability.
 */
class CaaDnsProbe : TlsProbe {
    override val id = "CAA_DNS"
    override val displayName = "CAA DNS Record Check (RFC 8659)"
    override val kind = ProbeKind.INFORMATIONAL

    /** dnsjava type constant for CAA (RFC 8659) — not in the public Type enum. */
    private val CAA_TYPE = 257

    override fun run(ctx: ProbeContext, result: TlsScanResult): List<TlsFinding> =
        runWithResult(ctx, result).findings

    override fun runWithResult(ctx: ProbeContext, result: TlsScanResult): ProbeResult {
        val started = System.currentTimeMillis()
        val elapsed = { System.currentTimeMillis() - started }

        if (!ctx.allowExternalQueries) {
            return ProbeResult.notApplicable(id, displayName,
                "External queries disabled in ProbeContext", elapsed())
        }
        if (ctx.host.matches(Regex("^[0-9.:]+$"))) {
            return ProbeResult.notApplicable(id, displayName,
                "Target is an IP address; CAA records are name-based", elapsed())
        }

        val records = try {
            lookupCaaWithParentWalk(ctx.host)
        } catch (e: Exception) {
            return ProbeResult.error(id, displayName,
                "DNS CAA query failed: ${e.message}", elapsed())
        }

        if (records.isEmpty()) {
            val finding = buildNoRecordsFinding(ctx.host)
            synchronized(result) { result.findings.add(finding) }
            return ProbeResult.potentiallyVulnerable(id, displayName, listOf(finding),
                elapsed(), "No CAA records for ${ctx.host} or any parent zone")
        }

        // Records exist — INFORMATION finding only, never HIGH/MEDIUM.
        val issueRecords = records.filter { it.tag == "issue" }
        val issueWildRecords = records.filter { it.tag == "issuewild" }
        val iodefRecords = records.filter { it.tag == "iodef" }

        // Special case: issue ";" alone means "forbid all issuance".
        val forbidsAll = issueRecords.size == 1 &&
            issueRecords[0].value.trim().let { it == ";" || it.isEmpty() } &&
            issueWildRecords.isEmpty()

        val finding = if (forbidsAll) {
            buildForbidsAllFinding(ctx.host)
        } else {
            buildRecordsPresentFinding(ctx.host, issueRecords, issueWildRecords,
                iodefRecords, records)
        }
        synchronized(result) { result.findings.add(finding) }

        return ProbeResult.notVulnerable(id, displayName, elapsed())
            .copy(message = buildSummaryMessage(issueRecords, issueWildRecords, iodefRecords))
    }

    // -------------------------------------------------------------------
    // DNS lookup with tree-walk (RFC 8659 §3)
    // -------------------------------------------------------------------

    private data class CaaRecord(val flags: Int, val tag: String, val value: String)

    /**
     * Look up CAA records for the given hostname. If none at the exact name, walk up
     * the DNS tree (drop leftmost label, repeat) until a record is found or the apex
     * is reached. Returns empty list if no records found anywhere along the walk.
     */
    private fun lookupCaaWithParentWalk(host: String): List<CaaRecord> {
        val labels = host.trimEnd('.').split('.')
        // Walk from most-specific to 2-label apex (no CAA on TLD).
        for (numLabels in labels.size downTo 2) {
            val domain = labels.takeLast(numLabels).joinToString(".")
            val records = queryCaa(domain)
            if (records.isNotEmpty()) return records
        }
        return emptyList()
    }

    private fun queryCaa(domain: String): List<CaaRecord> {
        return try {
            val lookup = Lookup(domain, CAA_TYPE)
            lookup.run() ?: return emptyList()
            lookup.answers?.mapNotNull { parseCaaRecord(it) } ?: emptyList()
        } catch (_: Exception) {
            emptyList()
        }
    }

    /**
     * Parse a raw DNS CAA record. dnsjava renders CAA via `rdataToString()` as
     * `<flags> <tag> "<value>"`, e.g. `0 issue "letsencrypt.org"`.
     */
    private fun parseCaaRecord(record: Record): CaaRecord? {
        return try {
            val text = record.rdataToString().trim()
            val parts = text.split(" ", limit = 3)
            if (parts.size < 3) return null
            val flags = parts[0].toIntOrNull() ?: 0
            val tag = parts[1].lowercase()
            val value = parts[2].trim('"').trim()
            CaaRecord(flags, tag, value)
        } catch (_: Exception) {
            null
        }
    }

    // -------------------------------------------------------------------
    // Finding builders — all INFORMATION or LOW, never HIGH/MEDIUM
    // -------------------------------------------------------------------

    private fun buildNoRecordsFinding(host: String): TlsFinding = TlsFinding(
        id = "CAA_NO_RECORDS",
        title = "No CAA DNS Records Found for $host",
        severity = TlsSeverity.LOW,
        confidence = TlsConfidence.FIRM,
        descriptionHtml = """
            <p><b>Summary:</b> No CAA (Certification Authority Authorization) DNS records are
            configured for <code>$host</code> or any parent zone (RFC 8659). Any CA in the
            WebPKI trust store may issue a certificate for this domain without restriction.</p>
            <p>CAA records let a domain owner specify which CAs may issue certificates.
            Without CAA, any of the ~100+ publicly-trusted CAs can issue a certificate for
            this domain. CAA is a defense-in-depth control — it does not prevent all
            certificate mis-issuance, but it raises the bar.</p>
            <p><b>Historical context:</b> major CA incidents (DigiNotar 2011, WoSign 2016)
            involved unauthorized certificate issuance that CAA would have blocked if enforced.</p>
            <p><b>Compliance:</b> CA/Browser Forum Baseline Requirements §3.2.2.8 requires CAs
            to check CAA records before issuance.</p>
        """.trimIndent(),
        remediationHtml = """
            <p>Add CAA records to your DNS zone. Example for Let's Encrypt:</p>
            <pre>
$host. IN CAA 0 issue "letsencrypt.org"
$host. IN CAA 0 issuewild ";"
$host. IN CAA 0 iodef "mailto:security@yourdomain.com"
            </pre>
            <p>Use <a href="https://sslmate.com/caa/">https://sslmate.com/caa/</a> to generate
            records for your specific CA.</p>
        """.trimIndent(),
        references = listOf(
            "https://datatracker.ietf.org/doc/html/rfc8659",
            "https://sslmate.com/caa/",
            "https://cabforum.org/working-groups/server/baseline-requirements/",
        )
    )

    private fun buildForbidsAllFinding(host: String): TlsFinding = TlsFinding(
        id = "CAA_NO_ISSUE_ALLOWED",
        title = "CAA Forbids All Certificate Issuance for $host",
        severity = TlsSeverity.INFO,
        confidence = TlsConfidence.CERTAIN,
        descriptionHtml = """
            <p><b>Summary:</b> CAA record <code>issue ";"</code> explicitly forbids all CAs
            from issuing certificates for <code>$host</code>.</p>
            <p>The certificate currently in use must have been issued before this restriction
            was published, or the CAA record is a misconfiguration.</p>
        """.trimIndent(),
        remediationHtml = """
            <p>If this is intentional, no action needed. If the domain needs a certificate,
            add a CAA <code>issue</code> record for the relevant CA (see
            <a href="https://sslmate.com/caa/">sslmate.com/caa/</a>).</p>
        """.trimIndent(),
        references = listOf(
            "https://datatracker.ietf.org/doc/html/rfc8659",
        )
    )

    private fun buildRecordsPresentFinding(
        host: String,
        issue: List<CaaRecord>,
        issuewild: List<CaaRecord>,
        iodef: List<CaaRecord>,
        all: List<CaaRecord>,
    ): TlsFinding {
        val authorizedCas = (issue.map { it.value } + issuewild.map { it.value })
            .filter { it != ";" && it.isNotBlank() }
            .distinct()

        val recordsHtml = all.joinToString("") { rec ->
            "<li><code>CAA ${rec.flags} ${rec.tag} \"${rec.value}\"</code></li>"
        }

        val iodefSection = if (iodef.isEmpty())
            """<p><b>Note:</b> No <code>iodef</code> tag configured. Without iodef, you will
               not receive notifications if a CA attempts to issue a certificate in violation
               of your CAA policy. Consider adding
               <code>iodef "mailto:security@yourdomain.com"</code>.</p>""".trimIndent()
        else
            """<p><b>Incident reporting:</b> ${iodef.joinToString(", ") { "<code>${it.value}</code>" }}</p>"""

        val description = """
            <p><b>Summary:</b> CAA records are configured for <code>$host</code>, restricting
            certificate issuance to ${authorizedCas.size} authorized CA(s).</p>
            <p><b>CAA records found:</b></p>
            <ul>$recordsHtml</ul>
            $iodefSection
        """.trimIndent()

        val remediation = if (iodef.isEmpty())
            """<p>Add an <code>iodef</code> tag to receive CA mis-issuance notifications:</p>
               <pre>$host. IN CAA 0 iodef "mailto:security@yourdomain.com"</pre>""".trimIndent()
        else
            """<p>No action needed — CAA is properly configured with both issuance restrictions
               and incident reporting.</p>""".trimIndent()

        return TlsFinding(
            id = "CAA_RECORDS_PRESENT",
            title = "CAA DNS Records Present for $host",
            severity = TlsSeverity.INFO,
            confidence = TlsConfidence.CERTAIN,
            descriptionHtml = description,
            remediationHtml = remediation,
            references = listOf(
                "https://datatracker.ietf.org/doc/html/rfc8659",
                "https://sslmate.com/caa/",
            )
        )
    }

    private fun buildSummaryMessage(
        issue: List<CaaRecord>,
        issuewild: List<CaaRecord>,
        iodef: List<CaaRecord>,
    ): String = "${issue.size} issue / ${issuewild.size} issuewild / " +
        "${iodef.size} iodef record(s)" +
        if (iodef.isEmpty()) " (no iodef — consider adding)" else ""
}
