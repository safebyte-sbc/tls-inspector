package io.safebyte.tlsinspector.probes

import io.safebyte.tlsinspector.ProbeContext
import io.safebyte.tlsinspector.TlsConfidence
import io.safebyte.tlsinspector.TlsScanResult
import io.safebyte.tlsinspector.TlsSeverity
import io.safebyte.tlsinspector.reporting.TlsFinding
import java.net.URL
import java.security.cert.CRLReason
import java.security.cert.CertificateFactory
import java.security.cert.X509CRL
import java.security.cert.X509Certificate

/**
 * CRL Revocation Probe — checks whether the leaf certificate is revoked via CRL.
 *
 * Falls back to CRL only if OCSP probe was NOT_APPLICABLE or failed. When OCSP was
 * conclusive (GOOD or REVOKED), CRL adds redundant confirmation — we skip to save time.
 *
 * Gaps documented:
 * - CRL signature verification is NOT performed (trust CA URL implicitly). Full chain
 *   validation would require fetching the issuer cert, which is deferred to MS E.
 * - Delta CRLs not supported — only base CRLs.
 */
class CrlRevocationProbe : TlsProbe {
    override val id = "CRL_REVOCATION"
    override val displayName = "CRL Revocation Check"
    override val kind = ProbeKind.INFORMATIONAL

    override fun run(ctx: ProbeContext, result: TlsScanResult): List<TlsFinding> =
        runWithResult(ctx, result).findings

    override fun runWithResult(ctx: ProbeContext, result: TlsScanResult): ProbeResult {
        val started = System.currentTimeMillis()
        val elapsed = { System.currentTimeMillis() - started }

        if (!ctx.allowExternalQueries) {
            return ProbeResult.notApplicable(id, displayName,
                "External queries disabled in ProbeContext", elapsed())
        }

        // If OCSP already confirmed GOOD or REVOKED, skip CRL (redundant + slow)
        val ocspResult = result.probeResults.find { it.probeId == "OCSP_REVOCATION" }
        if (ocspResult?.verdict == Verdict.NOT_VULNERABLE || ocspResult?.verdict == Verdict.VULNERABLE) {
            return ProbeResult.notApplicable(id, displayName,
                "Skipped — OCSP revocation check was conclusive (${ocspResult.verdict.displayName})", elapsed())
        }

        val leaf = result.leafCertificate
            ?: return ProbeResult.notApplicable(id, displayName,
                "No leaf certificate captured — run CERT_VALIDATION probe first", elapsed())

        val crlUrls = leaf.crlDistributionPoints
        if (crlUrls.isEmpty()) {
            return ProbeResult.notApplicable(id, displayName,
                "No CRL Distribution Points in certificate", elapsed())
        }

        // Try each CRL URL — use first that succeeds
        val timeoutMs = ctx.budget.handshakeTimeout.toMillis().toInt()
        for (crlUrl in crlUrls.take(3)) {
            if (ctx.cancelled()) break
            try {
                val crl = fetchCrl(crlUrl, timeoutMs)
                val serialNumber = java.math.BigInteger(leaf.serialNumberHex, 16)
                val entry = crl.getRevokedCertificate(serialNumber)

                if (entry != null) {
                    val revokedAt = entry.revocationDate
                    val reason = try {
                        entry.revocationReason?.name ?: "UNSPECIFIED"
                    } catch (_: Exception) { "UNSPECIFIED" }

                    val finding = TlsFinding(
                        id = "CRL_REVOCATION:certificate_revoked",
                        title = "Certificate Revoked (CRL)",
                        severity = TlsSeverity.CRITICAL,
                        confidence = TlsConfidence.FIRM,
                        descriptionHtml = """
                            <p><b>Summary:</b> The server certificate serial number appears on the
                            Certificate Revocation List published by the issuing CA. The certificate
                            must not be trusted.</p>
                            <p><b>Serial number:</b> ${leaf.serialNumberHex}</p>
                            <p><b>Revoked at:</b> $revokedAt</p>
                            <p><b>Reason:</b> $reason (RFC 5280 §5.3.1)</p>
                            <p><b>CRL URL:</b> <code>$crlUrl</code></p>
                            <p><b>Note:</b> CRL signature not verified (issuer cert fetch deferred to MS E).
                            Confidence: FIRM (not CERTAIN).</p>
                            <p><b>Compliance impact:</b> PCI DSS §6.3.3, ETSI TS 119 312 §6.5.</p>
                        """.trimIndent(),
                        remediationHtml = "<p>Replace the server certificate immediately. " +
                            "Investigate the reason for revocation and follow CA incident response procedures. " +
                            "If keyCompromise, rotate the private key before requesting a new certificate.</p>",
                        references = listOf(
                            "https://datatracker.ietf.org/doc/html/rfc5280#section-5",
                            "https://datatracker.ietf.org/doc/html/rfc5280#section-5.3.1",
                        )
                    )
                    synchronized(result) { result.findings.add(finding) }
                    return ProbeResult.vulnerable(id, displayName, listOf(finding), elapsed(),
                        "Certificate is REVOKED in CRL (reason=$reason, revokedAt=$revokedAt)")
                }

                // Not found in this CRL — certificate is not revoked
                return ProbeResult.notVulnerable(id, displayName, elapsed())
                    .copy(message = "CRL: Serial number not in revocation list (CRL updated ${crl.thisUpdate})")
            } catch (e: Exception) {
                // Try next URL
                continue
            }
        }

        return ProbeResult.error(id, displayName,
            "All CRL URLs failed (tried ${crlUrls.take(3).size})", elapsed())
    }

    private fun fetchCrl(url: String, timeoutMs: Int): X509CRL {
        val conn = URL(url).openConnection()
        conn.connectTimeout = timeoutMs
        conn.readTimeout = timeoutMs
        val bytes = conn.getInputStream().use { it.readBytes() }
        val factory = CertificateFactory.getInstance("X.509")
        return factory.generateCRL(bytes.inputStream()) as X509CRL
    }
}
