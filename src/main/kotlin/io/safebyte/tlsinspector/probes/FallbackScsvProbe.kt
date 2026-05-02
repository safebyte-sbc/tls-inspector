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
 * TLS_FALLBACK_SCSV Honored probe (RFC 7507).
 *
 * TLS_FALLBACK_SCSV (0x5600) is a signaling cipher suite value defined in RFC 7507
 * to prevent protocol downgrade attacks. When a client sends TLS_FALLBACK_SCSV in
 * its ClientHello at a version lower than its maximum supported version, a correctly
 * implemented server MUST respond with alert 86 (inappropriate_fallback) if it supports
 * a higher version.
 *
 * This probe:
 *  1. Identifies the two highest supported TLS protocols
 *  2. Sends a ClientHello at the second-highest version (simulating a downgrade)
 *     with TLS_FALLBACK_SCSV appended to the cipher list
 *  3. Checks if the server responds with alert 86 (honored) or proceeds normally
 *
 * A server that does NOT respond with alert 86 is vulnerable to downgrade attacks.
 *
 * Active probe — one TCP connection.
 */
class FallbackScsvProbe : TlsProbe {
    override val id = "FALLBACK_SCSV"
    override val displayName = "TLS_FALLBACK_SCSV Honored (RFC 7507)"
    override val kind = ProbeKind.VULNERABILITY

    override fun run(ctx: ProbeContext, result: TlsScanResult): List<TlsFinding> {
        return runWithResult(ctx, result).findings
    }

    override fun runWithResult(ctx: ProbeContext, result: TlsScanResult): ProbeResult {
        val started = System.currentTimeMillis()

        // Collect all offered protocols except SSL 2.0, sorted ascending by version
        val supported = TlsProtocol.entries
            .filter { proto ->
                proto != TlsProtocol.SSL_2_0 &&
                result.protocolsOffered[proto] == ProtocolStatus.OFFERED
            }
            .sortedBy { it.major * 256 + it.minor }

        if (supported.size < 2) {
            return ProbeResult.notApplicable(id, displayName,
                "Fewer than 2 TLS protocols offered — downgrade test not applicable",
                System.currentTimeMillis() - started)
        }

        val highest = supported.last()
        val lower = supported[supported.size - 2]

        // Build a ClientHello at the lower version with TLS_FALLBACK_SCSV
        val clientHello = ClientHelloBuilder.build(
            version = lower,
            sni = ctx.sni,
            cipherSuites = ClientHelloBuilder.DEFAULT_CIPHER_SUITES,
            includeFallbackScsv = true,
        )

        val outcome = TlsConnector(ctx).probeRawAfterHello(clientHello, ByteArray(0))
        if (outcome is RawProbeOutcome.Error) {
            return ProbeResult.error(id, displayName,
                "I/O error: ${outcome.message}",
                System.currentTimeMillis() - started)
        }

        val ok = outcome as RawProbeOutcome.Ok

        // Check the handshake-phase response for alert 86 (inappropriate_fallback)
        val alert = HandshakeParser.firstAlertDescription(ok.handshakePhase)

        if (alert == 86) {
            // Server correctly honored FALLBACK_SCSV and rejected the downgrade
            return ProbeResult.notVulnerable(id, displayName,
                System.currentTimeMillis() - started)
        }

        // Server accepted the downgraded connection — FALLBACK_SCSV not honored
        val finding = TlsFinding(
            id = "FALLBACK_SCSV:not_honored",
            title = "TLS_FALLBACK_SCSV Not Honored (RFC 7507)",
            severity = TlsSeverity.LOW,
            confidence = TlsConfidence.CERTAIN,
            descriptionHtml = """
                <p><b>Summary:</b> The server accepted a downgraded connection from ${highest.displayName}
                to ${lower.displayName} when TLS_FALLBACK_SCSV was included, without responding with
                alert 86 (inappropriate_fallback).</p>
                <p>RFC 7507 defines TLS_FALLBACK_SCSV as a mechanism to prevent protocol downgrade
                attacks. When a client includes this value in its cipher list at a version lower than
                its maximum, a properly implemented server MUST reject the connection with
                <code>inappropriate_fallback</code> (alert 86) if it supports a higher version.</p>
                <p>Without FALLBACK_SCSV enforcement, a network attacker who can interfere with
                TLS handshakes (e.g. via TCP RST injection) can force clients to downgrade to
                older, potentially vulnerable TLS versions. This is the mechanism that POODLE
                exploits (CVE-2014-3566).</p>
                <p><b>Compliance impact:</b> NIST SP 800-52r2 §3.5; PCI DSS 4.0 §4.2.1
                (anti-downgrade mechanisms recommended).</p>
            """.trimIndent(),
            remediationHtml = "<p>Enable TLS_FALLBACK_SCSV support on the server. For OpenSSL " +
                "1.0.1j+ / 1.0.0o+ / 0.9.8zc+: add <code>SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3</code> " +
                "and ensure OpenSSL is recent enough to handle FALLBACK_SCSV automatically. " +
                "For nginx: upgrade to 1.7.4+ which enables it by default.</p>",
            references = listOf(
                "https://tools.ietf.org/html/rfc7507",
                "https://nvd.nist.gov/vuln/detail/CVE-2014-3566",
            )
        )
        result.findings.add(finding)
        return ProbeResult.vulnerable(id, displayName, listOf(finding),
            System.currentTimeMillis() - started,
            "Downgrade ${highest.displayName} → ${lower.displayName} accepted (no alert 86)")
    }
}
