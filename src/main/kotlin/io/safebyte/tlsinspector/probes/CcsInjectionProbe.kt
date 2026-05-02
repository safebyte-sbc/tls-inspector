package io.safebyte.tlsinspector.probes

import io.safebyte.tlsinspector.ClientHelloBuilder
import io.safebyte.tlsinspector.HandshakeParser
import io.safebyte.tlsinspector.ProbeContext
import io.safebyte.tlsinspector.ProtocolStatus
import io.safebyte.tlsinspector.RawProbeOutcome
import io.safebyte.tlsinspector.TlsConfidence
import io.safebyte.tlsinspector.TlsConnector
import io.safebyte.tlsinspector.TlsProtocol
import io.safebyte.tlsinspector.TlsScanResult
import io.safebyte.tlsinspector.TlsSeverity
import io.safebyte.tlsinspector.reporting.TlsFinding

/**
 * CCS Injection (CVE-2014-0224) probe — OpenSSL ChangeCipherSpec injection.
 *
 * CVE-2014-0224 allows a MITM attacker to inject a premature ChangeCipherSpec message
 * during the TLS handshake, forcing both client and server to use weak keying material.
 * Vulnerable servers accept a CCS record before the ServerHelloDone.
 *
 * This probe sends:
 *  1. A standard ClientHello
 *  2. Immediately followed by a CCS record
 *
 * Expected responses:
 *  - Alert 10 (unexpected_message) → NOT_VULNERABLE (server correctly rejects premature CCS)
 *  - Alert 20 (bad_record_mac) → VULNERABLE (server accepted CCS, encryption state corrupted)
 *  - No alert / other → POTENTIALLY_VULNERABLE (inconclusive)
 *
 * Active probe — one TCP connection.
 */
class CcsInjectionProbe : TlsProbe {
    override val id = "CCS_INJECTION"
    override val displayName = "CCS Injection (CVE-2014-0224)"
    override val kind = ProbeKind.VULNERABILITY

    override fun run(ctx: ProbeContext, result: TlsScanResult): List<TlsFinding> {
        return runWithResult(ctx, result).findings
    }

    override fun runWithResult(ctx: ProbeContext, result: TlsScanResult): ProbeResult {
        val started = System.currentTimeMillis()

        // Pick the highest TLS 1.0/1.1/1.2 version offered
        val proto = listOf(TlsProtocol.TLS_1_2, TlsProtocol.TLS_1_1, TlsProtocol.TLS_1_0)
            .firstOrNull { result.protocolsOffered[it] == ProtocolStatus.OFFERED }
            ?: return ProbeResult.notApplicable(id, displayName,
                "No TLS 1.0/1.1/1.2 offered — CCS injection probe cannot run",
                System.currentTimeMillis() - started)

        val clientHello = ClientHelloBuilder.build(
            version = proto,
            sni = ctx.sni,
            cipherSuites = ClientHelloBuilder.DEFAULT_CIPHER_SUITES,
        )

        // Build a ChangeCipherSpec (ContentType 0x14) record
        // Format: ContentType(1) + ProtocolVersion(2) + Length(2) + CCS payload (1 byte: 0x01)
        val ccsRecord = byteArrayOf(
            0x14,                         // ContentType: change_cipher_spec
            proto.major.toByte(),         // ProtocolVersion major
            proto.minor.toByte(),         // ProtocolVersion minor
            0x00, 0x01,                   // Length: 1 byte
            0x01,                         // CCS payload
        )

        val outcome = TlsConnector(ctx).probeRawAfterHello(clientHello, ccsRecord)
        if (outcome is RawProbeOutcome.Error) {
            return ProbeResult.error(id, displayName,
                "I/O error: ${outcome.message}",
                System.currentTimeMillis() - started)
        }

        val ok = outcome as RawProbeOutcome.Ok

        // Parse the alert from the after-handshake response (server's reaction to our CCS)
        val alert = HandshakeParser.firstAlertDescription(ok.afterHandshake)

        return when (alert) {
            10 -> {
                // unexpected_message — server correctly rejected premature CCS
                ProbeResult.notVulnerable(id, displayName, System.currentTimeMillis() - started)
            }
            20 -> {
                // bad_record_mac — server accepted the CCS and then tried to decrypt with bad keys
                val finding = TlsFinding(
                    id = "CCS_INJECTION:premature_ccs_accepted",
                    title = "CCS Injection: Premature ChangeCipherSpec Accepted (CVE-2014-0224)",
                    severity = TlsSeverity.HIGH,
                    confidence = TlsConfidence.CERTAIN,
                    descriptionHtml = """
                        <p><b>Summary:</b> The server accepted a premature ChangeCipherSpec message
                        and responded with alert 20 (bad_record_mac), indicating it processed the CCS
                        and switched encryption state prematurely.</p>
                        <p>CVE-2014-0224 (OpenSSL CCS Injection) allows a man-in-the-middle attacker
                        to inject a ChangeCipherSpec record before the ServerHelloDone, forcing both
                        client and server to use weak keying material derived from zero-length pre-master
                        secrets. This allows the attacker to decrypt and manipulate all subsequent
                        traffic in the session.</p>
                        <p>The vulnerability affects OpenSSL versions prior to 0.9.8za, 1.0.0m,
                        and 1.0.1h. It requires both client and server to be vulnerable for full
                        exploitation, but a vulnerable server alone is at risk when paired with a
                        vulnerable client.</p>
                        <p><b>CVE:</b> CVE-2014-0224</p>
                        <p><b>Compliance impact:</b> PCI DSS 4.0 §6.3 (patching critical
                        vulnerabilities within 30 days); NIST NVD CVSS score: 7.4 (HIGH).</p>
                    """.trimIndent(),
                    remediationHtml = "<p>Update OpenSSL to 0.9.8za, 1.0.0m, 1.0.1h or later. " +
                        "Patching is the only effective remediation — there is no configuration " +
                        "workaround for CVE-2014-0224.</p>",
                    references = listOf(
                        "https://nvd.nist.gov/vuln/detail/CVE-2014-0224",
                        "https://www.openssl.org/news/secadv/20140605.txt",
                        "https://ccsinjection.lepidum.co.jp/",
                    )
                )
                result.findings.add(finding)
                ProbeResult.vulnerable(id, displayName, listOf(finding),
                    System.currentTimeMillis() - started,
                    "Premature CCS accepted on ${proto.displayName} (alert 20)")
            }
            null -> {
                // No alert received — inconclusive
                val finding = TlsFinding(
                    id = "CCS_INJECTION:no_alert_on_premature_ccs",
                    title = "CCS Injection: Inconclusive Response to Premature CCS (CVE-2014-0224)",
                    severity = TlsSeverity.MEDIUM,
                    confidence = TlsConfidence.TENTATIVE,
                    descriptionHtml = """
                        <p><b>Summary:</b> The server sent no alert in response to a premature
                        ChangeCipherSpec record — the expected response for a correct implementation
                        is alert 10 (unexpected_message). The absence of a response is inconclusive.</p>
                        <p>CVE-2014-0224 (OpenSSL CCS Injection) allows MITM attackers to force
                        weak keying material. This finding requires manual verification.</p>
                        <p><b>CVE:</b> CVE-2014-0224</p>
                    """.trimIndent(),
                    remediationHtml = "<p>Verify OpenSSL version is 0.9.8za / 1.0.0m / 1.0.1h or later. " +
                        "Manual verification with Metasploit module <code>auxiliary/scanner/ssl/openssl_ccs</code> " +
                        "is recommended.</p>",
                    references = listOf(
                        "https://nvd.nist.gov/vuln/detail/CVE-2014-0224",
                    )
                )
                result.findings.add(finding)
                ProbeResult.potentiallyVulnerable(id, displayName, listOf(finding),
                    System.currentTimeMillis() - started,
                    "No alert on premature CCS — inconclusive")
            }
            else -> {
                // Any other alert code — server rejected CCS with a different error, treat as not vulnerable
                ProbeResult.notVulnerable(id, displayName, System.currentTimeMillis() - started)
            }
        }
    }
}
