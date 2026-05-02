package io.safebyte.tlsinspector.probes

import io.safebyte.tlsinspector.CipherFlag
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
 * BEAST (CVE-2011-3389) — ported from validated standalone.
 *
 * Trigger: Server supports SSLv3 or TLS 1.0 with a CBC cipher AND
 * TLS 1.0 is the highest supported protocol (making downgrade realistic).
 *
 * First checks from cipher enumeration results; falls back to active CBC handshake probe.
 * Reports VULNERABLE if TLS 1.0 is highest protocol; POTENTIALLY_VULNERABLE if TLS 1.2+ also available.
 */
class BeastProbe : TlsProbe {
    override val id = "BEAST"
    override val displayName = "BEAST (CVE-2011-3389)"
    override val kind = ProbeKind.VULNERABILITY

    override fun run(ctx: ProbeContext, result: TlsScanResult): List<TlsFinding> =
        runWithResult(ctx, result).findings

    override fun runWithResult(ctx: ProbeContext, result: TlsScanResult): ProbeResult {
        val started = System.currentTimeMillis()

        val ssl3Offered  = result.protocolsOffered[TlsProtocol.SSL_3_0] == ProtocolStatus.OFFERED
        val tls10Offered = result.protocolsOffered[TlsProtocol.TLS_1_0] == ProtocolStatus.OFFERED

        if (!ssl3Offered && !tls10Offered) {
            return ProbeResult.notApplicable(id, displayName,
                "SSLv3 and TLS 1.0 not offered — BEAST does not apply",
                System.currentTimeMillis() - started)
        }

        // First check from cipher enumeration results (preferred — no additional network I/O)
        var cbcVersionFound: TlsProtocol? = null
        for (version in listOf(TlsProtocol.SSL_3_0, TlsProtocol.TLS_1_0)) {
            if (result.protocolsOffered[version] != ProtocolStatus.OFFERED) continue
            val ciphers = result.ciphersByProtocol[version] ?: continue
            if (ciphers.any { CipherFlag.CBC_NO_AEAD in it.flags }) {
                cbcVersionFound = version
                break
            }
        }

        // Fall back to active probe if cipher enumeration data not available
        if (cbcVersionFound == null) {
            for (version in listOf(TlsProtocol.SSL_3_0, TlsProtocol.TLS_1_0)) {
                if (result.protocolsOffered[version] != ProtocolStatus.OFFERED) continue
                if (tryBcastHandshake(ctx, version)) {
                    cbcVersionFound = version
                    break
                }
            }
        }

        if (cbcVersionFound == null) {
            return ProbeResult.notVulnerable(id, displayName, System.currentTimeMillis() - started)
        }

        // Determine severity: if TLS 1.0 is the highest protocol → full VULNERABLE
        val higherProtosOffered = listOf(TlsProtocol.TLS_1_1, TlsProtocol.TLS_1_2, TlsProtocol.TLS_1_3)
            .any { result.protocolsOffered[it] == ProtocolStatus.OFFERED }

        val severity = if (!higherProtosOffered) TlsSeverity.HIGH else TlsSeverity.MEDIUM

        val finding = TlsFinding(
            id = "BEAST:cbc_on_${cbcVersionFound.name}",
            title = "BEAST: CBC Cipher on ${cbcVersionFound.displayName} (CVE-2011-3389)",
            severity = severity,
            confidence = TlsConfidence.CERTAIN,
            descriptionHtml = "<p><b>Summary:</b> Server accepts CBC ciphers on ${cbcVersionFound.displayName}. " +
                "BEAST (CVE-2011-3389) exploits a chosen-boundary attack against CBC cipher suites in TLS 1.0 and SSLv3. " +
                if (!higherProtosOffered) "No higher TLS version offered — downgrade feasible." else
                "Higher TLS versions are also offered — modern browsers prefer them." +
                "</p><p><b>CVE:</b> CVE-2011-3389.</p>",
            remediationHtml = "<p>Disable TLS 1.0 and SSLv3. Enable TLS 1.2+ only.</p>",
            references = listOf("https://nvd.nist.gov/vuln/detail/CVE-2011-3389")
        )
        synchronized(result) { result.findings.add(finding) }

        return if (!higherProtosOffered) {
            ProbeResult.vulnerable(id, displayName, listOf(finding),
                System.currentTimeMillis() - started,
                "CBC on ${cbcVersionFound.displayName}, no higher protocol — BEAST feasible")
        } else {
            ProbeResult.potentiallyVulnerable(id, displayName, listOf(finding),
                System.currentTimeMillis() - started,
                "CBC on ${cbcVersionFound.displayName} but TLS 1.2+ also offered")
        }
    }

    private fun tryBcastHandshake(ctx: ProbeContext, version: TlsProtocol): Boolean = try {
        val sni = if (version == TlsProtocol.SSL_3_0) "" else ctx.sni
        val hello = ClientHelloBuilder.build(version = version, sni = sni,
            cipherSuites = ClientHelloBuilder.CBC_CIPHER_CODES)
        val sock = TlsRawSocket.openSocket(ctx)
        val timeoutMs = ctx.budget.handshakeTimeout.toMillis().toInt()
        sock.use {
            sock.getOutputStream().write(hello); sock.getOutputStream().flush()
            val (rawBuf, _) = TlsRawSocket.readUntilServerHelloDone(sock, timeoutMs)
            val info = HandshakeParser(rawBuf).parseServerHello() ?: return@use false
            info.cipherSuite in ClientHelloBuilder.CBC_CIPHER_CODES
        }
    } catch (e: Exception) { false }
}
