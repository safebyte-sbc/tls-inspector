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
 * Raccoon Attack — CVE-2020-1968
 *
 * A server that reuses DHE public keys (Ys) across handshakes is vulnerable:
 * an attacker can exploit a timing side-channel in the DH pre-master-secret
 * stripping (leading-zero removal) to recover the PMS via dictionary attack.
 *
 * Detection heuristic: open 5 independent DHE handshakes and compare Ys values.
 * If any two are identical → key reuse → POTENTIALLY_VULNERABLE.
 *
 * Pre-condition: TLS 1.0/1.1/1.2 must be offered with at least one DHE cipher.
 */
class RaccoonProbe : TlsProbe {
    override val id = "RACCOON"
    override val displayName = "Raccoon DHE Key Reuse (CVE-2020-1968)"
    override val kind = ProbeKind.VULNERABILITY

    private val HANDSHAKES = 5

    override fun run(ctx: ProbeContext, result: TlsScanResult): List<TlsFinding> =
        runWithResult(ctx, result).findings

    override fun runWithResult(ctx: ProbeContext, result: TlsScanResult): ProbeResult {
        val started = System.currentTimeMillis()

        val hasLegacyTls = listOf(TlsProtocol.TLS_1_0, TlsProtocol.TLS_1_1, TlsProtocol.TLS_1_2)
            .any { result.protocolsOffered[it] == ProtocolStatus.OFFERED }

        if (!hasLegacyTls) {
            return ProbeResult.notApplicable(id, displayName,
                "No TLS 1.0/1.1/1.2 supported — Raccoon not applicable",
                System.currentTimeMillis() - started)
        }

        // Check that server offers DHE suites in cipher enumeration results
        // DHE = has FORWARD_SECRECY but key exchange is DHE (not ECDHE) — check name patterns
        val hasDheCiphers = listOf(TlsProtocol.TLS_1_0, TlsProtocol.TLS_1_1, TlsProtocol.TLS_1_2)
            .filter { result.protocolsOffered[it] == ProtocolStatus.OFFERED }
            .any { v ->
                result.ciphersByProtocol[v]?.any { c ->
                    c.keyExchange.contains("DHE", ignoreCase = true) &&
                    !c.keyExchange.contains("ECDHE", ignoreCase = true)
                } == true
            }

        if (!hasDheCiphers) {
            return ProbeResult.notApplicable(id, displayName,
                "No DHE cipher suites offered",
                System.currentTimeMillis() - started)
        }

        return try {
            runRaccoonCheck(ctx, result, started)
        } catch (e: Exception) {
            ProbeResult.error(id, displayName,
                "Raccoon probe error: ${e.javaClass.simpleName}: ${e.message}",
                System.currentTimeMillis() - started)
        }
    }

    private fun collectYsValues(ctx: ProbeContext): List<ByteArray?> {
        val timeoutMs = ctx.budget.handshakeTimeout.toMillis().toInt()
        return (1..HANDSHAKES).map {
            try {
                val sock = TlsRawSocket.openSocket(ctx)
                sock.use {
                    sock.getOutputStream().write(ClientHelloBuilder.buildDheRsaOnlyClientHello(ctx.sni))
                    sock.getOutputStream().flush()
                    val (rawBuf, seenDone) = TlsRawSocket.readUntilServerHelloDone(sock, timeoutMs)
                    if (!seenDone) return@use null
                    val skeBody = HandshakeParser.findServerKeyExchangeBody(rawBuf) ?: return@use null
                    HandshakeParser.parseServerKeyExchangeDhFull(skeBody)?.ysRaw
                }
            } catch (_: Exception) { null }
        }
    }

    private fun runRaccoonCheck(ctx: ProbeContext, result: TlsScanResult, started: Long): ProbeResult {
        val ysValues = collectYsValues(ctx)
        val successful = ysValues.filterNotNull()

        if (successful.isEmpty()) {
            return ProbeResult.notApplicable(id, displayName,
                "No successful DHE handshake — server may not support DHE with this cipher list",
                System.currentTimeMillis() - started)
        }

        val distinct = mutableListOf<ByteArray>()
        for (ys in successful) {
            if (distinct.none { it.contentEquals(ys) }) distinct += ys
        }

        if (distinct.size < successful.size) {
            val finding = TlsFinding(
                id = "RACCOON:dhe_ys_reuse",
                title = "Raccoon: DHE Public Key Reuse Detected (CVE-2020-1968)",
                severity = TlsSeverity.MEDIUM,
                confidence = TlsConfidence.FIRM,
                descriptionHtml = """
                    <p><b>Summary:</b> $HANDSHAKES DHE handshakes produced ${distinct.size} distinct Ys values
                    (${successful.size} successful). The server reuses DHE ephemeral public keys (Ys)
                    across independent connections.</p>
                    <p>The Raccoon Attack (CVE-2020-1968) exploits a timing side-channel in the TLS
                    pre-master-secret computation: when the first byte of DH(Ys, Yc) is zero, it is
                    stripped, shortening the pre-master-secret. This creates a timing difference that
                    leaks information allowing dictionary attacks to recover the PMS — but only when
                    the same Ys is reused. Servers with unique Ys per handshake are immune.</p>
                    <p><b>CVE:</b> CVE-2020-1968 | CVSS 3.7 (LOW — requires precise timing and MitM)</p>
                    <p><b>Compliance:</b> NIST SP 800-52r2 recommends ECDHE over DHE.</p>
                """.trimIndent(),
                remediationHtml = "<p>Disable DHE cipher suites; prefer ECDHE (e.g. x25519, secp256r1) " +
                    "which provides forward secrecy without the DH key-reuse problem. " +
                    "If DHE must be kept, ensure the implementation generates a fresh Ys per handshake.</p>",
                references = listOf(
                    "https://raccoon-attack.com/",
                    "https://nvd.nist.gov/vuln/detail/CVE-2020-1968",
                )
            )
            synchronized(result) { result.findings.add(finding) }
            return ProbeResult.potentiallyVulnerable(id, displayName, listOf(finding),
                System.currentTimeMillis() - started,
                "DH Ys reuse: ${successful.size} handshakes, ${distinct.size} distinct Ys values")
        }

        return ProbeResult.notVulnerable(id, displayName, System.currentTimeMillis() - started)
    }
}
