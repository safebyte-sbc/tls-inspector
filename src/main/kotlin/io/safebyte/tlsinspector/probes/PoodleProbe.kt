package io.safebyte.tlsinspector.probes

import io.safebyte.tlsinspector.ClientHelloBuilder
import io.safebyte.tlsinspector.HandshakeParser
import io.safebyte.tlsinspector.ProbeContext
import io.safebyte.tlsinspector.ProtocolStatus
import io.safebyte.tlsinspector.TlsConfidence
import io.safebyte.tlsinspector.TlsProtocol
import io.safebyte.tlsinspector.TlsRawSocket
import io.safebyte.tlsinspector.TlsScanResult
import io.safebyte.tlsinspector.TlsSeverity
import io.safebyte.tlsinspector.reporting.TlsFinding

/**
 * POODLE on SSLv3 (CVE-2014-3566) — ported from validated standalone.
 *
 * Detection:
 * 1. Server must support SSLv3 (from ProtocolEnumerationProbe)
 * 2. Try to negotiate SSLv3 with a CBC cipher — if succeeds → VULNERABLE
 * 3. If SSLv3 offered but no CBC cipher negotiated → POTENTIALLY_VULNERABLE
 *
 * Uses raw socket with SSLv3 ClientHello + CBC-only cipher list.
 */
class PoodleProbe : TlsProbe {
    override val id = "POODLE_SSLV3"
    override val displayName = "POODLE on SSLv3 (CVE-2014-3566)"
    override val kind = ProbeKind.VULNERABILITY

    override fun run(ctx: ProbeContext, result: TlsScanResult): List<TlsFinding> =
        runWithResult(ctx, result).findings

    override fun runWithResult(ctx: ProbeContext, result: TlsScanResult): ProbeResult {
        val started = System.currentTimeMillis()

        if (result.protocolsOffered[TlsProtocol.SSL_3_0] != ProtocolStatus.OFFERED) {
            return ProbeResult.notApplicable(id, displayName,
                "SSLv3 not offered — POODLE on SSLv3 cannot apply",
                System.currentTimeMillis() - started)
        }

        return try {
            val hello = ClientHelloBuilder.build(
                version = TlsProtocol.SSL_3_0,
                sni = "",  // SSLv3 doesn't support SNI
                cipherSuites = ClientHelloBuilder.CBC_CIPHER_CODES,
            )
            val sock = TlsRawSocket.openSocket(ctx)
            val timeoutMs = ctx.budget.handshakeTimeout.toMillis().toInt()
            val rawBuf = sock.use {
                sock.getOutputStream().write(hello)
                sock.getOutputStream().flush()
                val (buf, _) = TlsRawSocket.readUntilServerHelloDone(sock, timeoutMs)
                buf
            }

            val info = HandshakeParser(rawBuf).parseServerHello()

            if (info != null) {
                val cipherName = "0x${"%04X".format(info.cipherSuite)}"
                val isCbc = info.compressionMethod == 0 &&
                    !cipherName.contains("GCM") && !cipherName.contains("CCM") &&
                    !cipherName.contains("RC4")

                // Check if CBC cipher from known set
                val isCbcKnown = info.cipherSuite in ClientHelloBuilder.CBC_CIPHER_CODES

                if (isCbcKnown || isCbc) {
                    val finding = TlsFinding(
                        id = "POODLE_SSLV3:cbc_negotiated",
                        title = "POODLE Vulnerability (CVE-2014-3566)",
                        severity = TlsSeverity.HIGH,
                        confidence = TlsConfidence.CERTAIN,
                        descriptionHtml = """
                            <p><b>Summary:</b> The server offers SSLv3 with CBC cipher suites.
                            POODLE (CVE-2014-3566) allows a network attacker who can force a
                            downgrade to SSLv3 to recover plaintext bytes from CBC-encrypted
                            records using a padding oracle.</p>
                            <p>Negotiated cipher suite code: <code>0x${"%04X".format(info.cipherSuite)}</code></p>
                            <p><b>CVE:</b> CVE-2014-3566 | CVSS 3.4 (MEDIUM — requires MITM)</p>
                            <p><b>Compliance impact:</b> PCI DSS §4.2.1 prohibits SSLv3/SSLv2.
                            BNM/HCE requires TLS 1.2 minimum.</p>
                        """.trimIndent(),
                        remediationHtml = "<p>Disable SSLv3 on the server. Set minimum TLS version to TLS 1.2. " +
                            "In Apache: <code>SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1</code>. " +
                            "In Nginx: <code>ssl_protocols TLSv1.2 TLSv1.3;</code></p>",
                        references = listOf(
                            "https://www.openssl.org/~bodo/ssl-poodle.pdf",
                            "https://nvd.nist.gov/vuln/detail/CVE-2014-3566",
                        )
                    )
                    synchronized(result) { result.findings.add(finding) }
                    ProbeResult.vulnerable(id, displayName, listOf(finding),
                        System.currentTimeMillis() - started,
                        "SSLv3 with CBC cipher 0x${"%04X".format(info.cipherSuite)}")
                } else {
                    // SSLv3 accepted but non-CBC cipher (e.g. RC4)
                    val finding = TlsFinding(
                        id = "POODLE_SSLV3:non_cbc_cipher",
                        title = "POODLE (CVE-2014-3566) — SSLv3 Offered (Non-CBC Cipher)",
                        severity = TlsSeverity.MEDIUM,
                        confidence = TlsConfidence.FIRM,
                        descriptionHtml = "<p>SSLv3 is offered (POODLE applies to CBC ciphers). " +
                            "Non-CBC cipher negotiated: <code>0x${"%04X".format(info.cipherSuite)}</code>. " +
                            "SSLv3 must still be disabled as a deprecated protocol.</p>",
                        remediationHtml = "<p>Disable SSLv3 completely — it is deprecated per RFC 7568.</p>",
                        references = listOf("https://nvd.nist.gov/vuln/detail/CVE-2014-3566")
                    )
                    synchronized(result) { result.findings.add(finding) }
                    ProbeResult.potentiallyVulnerable(id, displayName, listOf(finding),
                        System.currentTimeMillis() - started,
                        "SSLv3 offered but non-CBC cipher negotiated")
                }
            } else {
                ProbeResult.notVulnerable(id, displayName, System.currentTimeMillis() - started)
            }
        } catch (e: Exception) {
            ProbeResult.error(id, displayName, "Error: ${e.message}", System.currentTimeMillis() - started)
        }
    }
}
