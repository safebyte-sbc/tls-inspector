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
 * CRIME (CVE-2012-4929) probe — TLS compression oracle.
 *
 * CRIME exploits TLS-layer compression (DEFLATE) to recover secrets from HTTPS
 * requests. When TLS compression is enabled, an attacker who can inject chosen
 * plaintext (e.g. via JavaScript in the same origin or CORS) can observe how
 * compressed ciphertext size changes to infer the plaintext byte-by-byte.
 *
 * This probe sends a ClientHello advertising DEFLATE compression (0x01) first,
 * then NULL (0x00). If the server responds with a ServerHello selecting compression
 * method 0x01 (DEFLATE), the server is vulnerable.
 *
 * Active probe — one TCP connection.
 */
class CrimeProbe : TlsProbe {
    override val id = "CRIME"
    override val displayName = "CRIME (CVE-2012-4929)"
    override val kind = ProbeKind.VULNERABILITY

    override fun run(ctx: ProbeContext, result: TlsScanResult): List<TlsFinding> {
        return runWithResult(ctx, result).findings
    }

    override fun runWithResult(ctx: ProbeContext, result: TlsScanResult): ProbeResult {
        val started = System.currentTimeMillis()

        // Pick the highest TLS 1.0/1.1/1.2 version the server offers
        val proto = listOf(TlsProtocol.TLS_1_2, TlsProtocol.TLS_1_1, TlsProtocol.TLS_1_0)
            .firstOrNull { result.protocolsOffered[it] == ProtocolStatus.OFFERED }
            ?: return ProbeResult.notApplicable(id, displayName,
                "No TLS 1.0/1.1/1.2 offered — CRIME probe cannot run",
                System.currentTimeMillis() - started)

        // Build ClientHello with DEFLATE (0x01) listed before NULL (0x00)
        val clientHello = ClientHelloBuilder.build(
            version = proto,
            sni = ctx.sni,
            cipherSuites = ClientHelloBuilder.DEFAULT_CIPHER_SUITES,
            compressionMethods = byteArrayOf(0x01, 0x00), // DEFLATE, then NULL
        )

        val outcome = TlsConnector(ctx).probeRawAfterHello(clientHello, ByteArray(0))
        if (outcome is RawProbeOutcome.Error) {
            return ProbeResult.error(id, displayName,
                "I/O error: ${outcome.message}",
                System.currentTimeMillis() - started)
        }

        val ok = outcome as RawProbeOutcome.Ok

        // Parse the compression byte from the ServerHello
        val compression = HandshakeParser.serverHelloCompression(ok.handshakePhase)
        if (compression == null || compression == 0x00) {
            // Server selected NULL compression — not vulnerable
            return ProbeResult.notVulnerable(id, displayName, System.currentTimeMillis() - started)
        }

        val compressionHex = "%02X".format(compression)

        val finding = TlsFinding(
            id = "CRIME:tls_compression_accepted",
            title = "CRIME: TLS Compression Enabled (CVE-2012-4929)",
            severity = TlsSeverity.HIGH,
            confidence = TlsConfidence.CERTAIN,
            descriptionHtml = """
                <p><b>Summary:</b> The server accepted TLS-layer DEFLATE compression (method 0x$compressionHex).</p>
                <p>CRIME (CVE-2012-4929) exploits TLS compression to recover plaintext secrets such as
                session cookies or authentication tokens from HTTPS traffic. When compression is enabled,
                an attacker who can inject controlled plaintext into requests (e.g. via JavaScript
                executing in the same browser session) can observe changes in compressed ciphertext size
                to recover secret values byte-by-byte. This attack does not require breaking encryption.</p>
                <p>TLS-layer compression was deprecated in RFC 7525 §3.3 (2015). No legitimate reason
                to enable it exists in 2026 — HTTP-level compression (Content-Encoding: gzip) is safer
                because it operates below the TLS encryption layer where secrets are already separated.</p>
                <p><b>CVE:</b> CVE-2012-4929</p>
                <p><b>Compliance impact:</b> PCI DSS 4.0 §4.2.1; NIST SP 800-52r2 §3.5
                (compression shall not be used).</p>
            """.trimIndent(),
            remediationHtml = "<p>Disable TLS-layer compression in the server configuration. " +
                "For OpenSSL-based servers: set <code>SSL_OP_NO_COMPRESSION</code> flag. " +
                "For nginx: ensure <code>ssl_compression off</code> (default since 1.5.8).</p>",
            references = listOf(
                "https://nvd.nist.gov/vuln/detail/CVE-2012-4929",
                "https://tools.ietf.org/html/rfc7525#section-3.3",
            )
        )
        result.findings.add(finding)
        return ProbeResult.vulnerable(id, displayName, listOf(finding),
            System.currentTimeMillis() - started,
            "TLS compression 0x$compressionHex accepted on ${proto.displayName}")
    }
}
