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
 * Sweet32 / 3DES Birthday Attack (CVE-2016-2183) — ported from validated standalone.
 *
 * Config check: server accepts any 3DES/DES cipher suite.
 * First checks cipher enumeration results (if available), then does active probe.
 */
class Sweet32Probe : TlsProbe {
    override val id = "SWEET32"
    override val displayName = "Sweet32 (CVE-2016-2183)"
    override val kind = ProbeKind.VULNERABILITY

    override fun run(ctx: ProbeContext, result: TlsScanResult): List<TlsFinding> =
        runWithResult(ctx, result).findings

    override fun runWithResult(ctx: ProbeContext, result: TlsScanResult): ProbeResult {
        val started = System.currentTimeMillis()

        // First check from cipher enumeration results
        for ((proto, ciphers) in result.ciphersByProtocol) {
            val found = ciphers.firstOrNull { CipherFlag.TRIPLE_DES_64BIT_BLOCK in it.flags }
            if (found != null) {
                return buildVulnerableResult(found.name, proto.displayName, result, started)
            }
        }

        // Fall back to active probe
        val versionsToTest = listOf(TlsProtocol.SSL_3_0, TlsProtocol.TLS_1_0, TlsProtocol.TLS_1_1, TlsProtocol.TLS_1_2)
            .filter { result.protocolsOffered[it] == ProtocolStatus.OFFERED }

        for (version in versionsToTest) {
            val cipherCode = tryTripleDesHandshake(ctx, version) ?: continue
            return buildVulnerableResult("0x${"%04X".format(cipherCode)}", version.displayName, result, started)
        }

        return ProbeResult.notVulnerable(id, displayName, System.currentTimeMillis() - started)
    }

    private fun buildVulnerableResult(
        cipherName: String, versionName: String, result: TlsScanResult, started: Long
    ): ProbeResult {
        val finding = TlsFinding(
            id = "SWEET32:3des_accepted",
            title = "Sweet32: 3DES Birthday Attack (CVE-2016-2183)",
            severity = TlsSeverity.MEDIUM,
            confidence = TlsConfidence.CERTAIN,
            descriptionHtml = "<p><b>Summary:</b> Server accepts 3DES cipher <code>$cipherName</code> on " +
                "$versionName. 3DES (64-bit block) is vulnerable to birthday attacks in long sessions " +
                "(~785 GB). Deprecated by NIST SP 800-131A.</p>" +
                "<p><b>CVE:</b> CVE-2016-2183. <b>Compliance:</b> PCI DSS §4.2.1.</p>",
            remediationHtml = "<p>Remove 3DES from TLS config. Add <code>:!3DES</code> to OpenSSL cipher string.</p>",
            references = listOf("https://sweet32.info/", "https://nvd.nist.gov/vuln/detail/CVE-2016-2183")
        )
        synchronized(result) { result.findings.add(finding) }
        return ProbeResult.vulnerable(id, displayName, listOf(finding),
            System.currentTimeMillis() - started, "3DES cipher $cipherName on $versionName")
    }

    private fun tryTripleDesHandshake(ctx: ProbeContext, version: TlsProtocol): Int? = try {
        val sni = if (version == TlsProtocol.SSL_3_0) "" else ctx.sni
        val hello = ClientHelloBuilder.build(version = version, sni = sni,
            cipherSuites = ClientHelloBuilder.TRIPLE_DES_CIPHER_CODES)
        val sock = TlsRawSocket.openSocket(ctx)
        val timeoutMs = ctx.budget.handshakeTimeout.toMillis().toInt()
        sock.use {
            sock.getOutputStream().write(hello); sock.getOutputStream().flush()
            val (rawBuf, _) = TlsRawSocket.readUntilServerHelloDone(sock, timeoutMs)
            val info = HandshakeParser(rawBuf).parseServerHello() ?: return@use null
            if (info.cipherSuite in ClientHelloBuilder.TRIPLE_DES_CIPHER_CODES) info.cipherSuite else null
        }
    } catch (e: Exception) { null }
}
