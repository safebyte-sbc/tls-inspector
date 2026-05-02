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
 * FREAK (CVE-2015-0204) — ported from validated standalone.
 *
 * Offer ONLY export-grade RSA cipher suites.
 * If the server accepts any of them → VULNERABLE.
 * Tests each supported protocol version (SSLv3, TLS 1.0–1.2).
 */
class FreakProbe : TlsProbe {
    override val id = "FREAK"
    override val displayName = "FREAK (CVE-2015-0204)"
    override val kind = ProbeKind.VULNERABILITY

    override fun run(ctx: ProbeContext, result: TlsScanResult): List<TlsFinding> =
        runWithResult(ctx, result).findings

    override fun runWithResult(ctx: ProbeContext, result: TlsScanResult): ProbeResult {
        val started = System.currentTimeMillis()

        val versionsToTest = listOf(TlsProtocol.SSL_3_0, TlsProtocol.TLS_1_0, TlsProtocol.TLS_1_1, TlsProtocol.TLS_1_2)
            .filter { result.protocolsOffered[it] == ProtocolStatus.OFFERED }

        if (versionsToTest.isEmpty()) {
            return ProbeResult.notApplicable(id, displayName,
                "No SSL3/TLS 1.0-1.2 supported", System.currentTimeMillis() - started)
        }

        for (version in versionsToTest) {
            val accepted = tryExportRsaHandshake(ctx, version) ?: continue
            val finding = TlsFinding(
                id = "FREAK:export_rsa_accepted:${version.name}",
                title = "FREAK: Export RSA Cipher Accepted (CVE-2015-0204)",
                severity = TlsSeverity.HIGH,
                confidence = TlsConfidence.CERTAIN,
                descriptionHtml = """
                    <p><b>Summary:</b> The server accepted an export-grade RSA cipher suite
                    (<code>0x${"%04X".format(accepted)}</code>) on ${version.displayName}.
                    FREAK (Factoring RSA Export Keys) allows a man-in-the-middle attacker to
                    downgrade a connection to a 512-bit RSA key that can be factored in hours.</p>
                    <p>Export cipher suites were intentionally weakened in the 1990s for US export
                    regulations. These restrictions are long gone, but some servers still support them.</p>
                    <p><b>CVE:</b> CVE-2015-0204 | CVSS 7.4 (HIGH)</p>
                    <p><b>Compliance impact:</b> PCI DSS §4.2.1 prohibits export-grade ciphers.</p>
                """.trimIndent(),
                remediationHtml = "<p>Disable all EXPORT cipher suites in the server TLS configuration. " +
                    "In OpenSSL: <code>!EXPORT</code> in the cipher string. " +
                    "In Apache: <code>SSLCipherSuite HIGH:!EXPORT:!aNULL:!eNULL</code></p>",
                references = listOf(
                    "https://nvd.nist.gov/vuln/detail/CVE-2015-0204",
                    "https://freakattack.com/",
                )
            )
            synchronized(result) { result.findings.add(finding) }
            return ProbeResult.vulnerable(id, displayName, listOf(finding),
                System.currentTimeMillis() - started,
                "Export RSA cipher 0x${"%04X".format(accepted)} accepted on ${version.displayName}")
        }
        return ProbeResult.notVulnerable(id, displayName, System.currentTimeMillis() - started)
    }

    private fun tryExportRsaHandshake(ctx: ProbeContext, version: TlsProtocol): Int? = try {
        val sni = if (version == TlsProtocol.SSL_3_0) "" else ctx.sni
        val hello = ClientHelloBuilder.build(
            version = version,
            sni = sni,
            cipherSuites = ClientHelloBuilder.EXPORT_RSA_CIPHER_CODES,
        )
        val sock = TlsRawSocket.openSocket(ctx)
        val timeoutMs = ctx.budget.handshakeTimeout.toMillis().toInt()
        sock.use {
            sock.getOutputStream().write(hello)
            sock.getOutputStream().flush()
            val (rawBuf, _) = TlsRawSocket.readUntilServerHelloDone(sock, timeoutMs)
            val info = HandshakeParser(rawBuf).parseServerHello() ?: return@use null
            if (info.cipherSuite in ClientHelloBuilder.EXPORT_RSA_CIPHER_CODES) info.cipherSuite else null
        }
    } catch (e: Exception) { null }
}
