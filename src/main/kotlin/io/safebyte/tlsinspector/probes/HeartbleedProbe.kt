package io.safebyte.tlsinspector.probes

import io.safebyte.tlsinspector.ClientHelloBuilder
import io.safebyte.tlsinspector.ProbeContext
import io.safebyte.tlsinspector.ProtocolStatus
import io.safebyte.tlsinspector.TlsConfidence
import io.safebyte.tlsinspector.TlsProtocol
import io.safebyte.tlsinspector.TlsRawSocket
import io.safebyte.tlsinspector.TlsScanResult
import io.safebyte.tlsinspector.TlsSeverity
import io.safebyte.tlsinspector.reporting.TlsFinding

/**
 * Heartbleed (CVE-2014-0160) — ported from validated standalone.
 *
 * Technique (sslyze approach):
 * 1. Send ClientHello with Heartbeat extension for TLS 1.2 (or highest < 1.3)
 * 2. Read until ServerHelloDone
 * 3. Send TWO heartbeat records: one with 16381-byte marker payload, one 3-byte
 * 4. If response contains the marker sequence (0x01 * 10) → server leaked memory → VULNERABLE
 *
 * Pre-condition: Skip if only TLS 1.3 is supported (TLS 1.3 predates Heartbleed).
 */
class HeartbleedProbe : TlsProbe {
    override val id = "HEARTBLEED"
    override val displayName = "Heartbleed (CVE-2014-0160)"
    override val kind = ProbeKind.VULNERABILITY

    private val MARKER = ByteArray(16381) { 0x01 }
    private val MARKER_CHECK = ByteArray(10) { 0x01 }

    override fun run(ctx: ProbeContext, result: TlsScanResult): List<TlsFinding> =
        runWithResult(ctx, result).findings

    override fun runWithResult(ctx: ProbeContext, result: TlsScanResult): ProbeResult {
        val started = System.currentTimeMillis()

        // Skip if only TLS 1.3 offered (not vulnerable to Heartbleed)
        val candidate = listOf(TlsProtocol.TLS_1_2, TlsProtocol.TLS_1_1, TlsProtocol.TLS_1_0)
            .firstOrNull { result.protocolsOffered[it] == ProtocolStatus.OFFERED }
            ?: return ProbeResult.notApplicable(id, displayName,
                "No TLS 1.0/1.1/1.2 — Heartbleed not applicable",
                System.currentTimeMillis() - started)

        return try {
            probe(ctx, result, candidate, started)
        } catch (e: Exception) {
            ProbeResult.error(id, displayName, "Error: ${e.message}", System.currentTimeMillis() - started)
        }
    }

    private fun probe(ctx: ProbeContext, result: TlsScanResult, version: TlsProtocol, started: Long): ProbeResult {
        val sock = TlsRawSocket.openSocket(ctx)
        return sock.use {
            val hello = ClientHelloBuilder.build(
                version = version,
                sni = ctx.sni,
                cipherSuites = listOf(0xC02F, 0xC030, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035),
                includeHeartbeat = true,
            )
            sock.getOutputStream().write(hello)
            sock.getOutputStream().flush()

            val timeoutMs = ctx.budget.handshakeTimeout.toMillis().toInt()
            val (rawBuf, seenDone) = TlsRawSocket.readUntilServerHelloDone(sock, timeoutMs)

            if (!seenDone) {
                return@use ProbeResult.notVulnerable(id, displayName, System.currentTimeMillis() - started)
            }

            // Send two heartbeat records
            val hbPayload = buildHeartbeatRecord(version, MARKER) +
                            buildHeartbeatRecord(version, byteArrayOf(0x01, 0x00, 0x00))
            sock.getOutputStream().write(hbPayload)
            sock.getOutputStream().flush()

            sock.soTimeout = timeoutMs
            val responseBytes = try {
                @Suppress("Since15")
                sock.getInputStream().readNBytes(16381)
            } catch (e: Exception) {
                ByteArray(0)
            }

            if (responseBytes.isEmpty()) {
                return@use ProbeResult.notVulnerable(id, displayName, System.currentTimeMillis() - started)
            }

            if (containsMarker(responseBytes, MARKER_CHECK)) {
                val finding = TlsFinding(
                    id = "HEARTBLEED:memory_leak_confirmed",
                    title = "Heartbleed — OpenSSL Memory Leak (CVE-2014-0160)",
                    severity = TlsSeverity.CRITICAL,
                    confidence = TlsConfidence.CERTAIN,
                    descriptionHtml = """
                        <p><b>Summary:</b> The server echoed back our Heartbeat marker bytes,
                        confirming CVE-2014-0160 (Heartbleed). An attacker can read up to 64 KB of
                        server memory per heartbeat request — including private keys, session tokens,
                        passwords, and other sensitive data.</p>
                        <p>Affected OpenSSL versions: 1.0.1 through 1.0.1f. The vulnerability affects
                        the Heartbeat extension implementation in OpenSSL's TLS/DTLS stack.</p>
                        <p><b>CVE:</b> CVE-2014-0160 | CVSS 7.5 (HIGH)</p>
                        <p><b>Compliance impact:</b> PCI DSS §6.3 (critical vulnerability — patch immediately).
                        BNM/HCE critical infrastructure — immediate disclosure required.</p>
                    """.trimIndent(),
                    remediationHtml = "<p>Upgrade OpenSSL to 1.0.1g or later, or 1.0.2 branch. " +
                        "After patching, rotate all private keys and SSL certificates immediately. " +
                        "Revoke and re-issue all server certificates. Invalidate all session tokens.</p>",
                    references = listOf(
                        "https://nvd.nist.gov/vuln/detail/CVE-2014-0160",
                        "https://heartbleed.com/",
                        "https://www.openssl.org/news/secadv/20140407.txt",
                    )
                )
                synchronized(result) { result.findings.add(finding) }
                ProbeResult.vulnerable(id, displayName, listOf(finding),
                    System.currentTimeMillis() - started, "Memory leak confirmed via heartbeat marker")
            } else {
                ProbeResult.notVulnerable(id, displayName, System.currentTimeMillis() - started)
            }
        }
    }

    private fun buildHeartbeatRecord(version: TlsProtocol, data: ByteArray): ByteArray {
        val innerLen = 1 + 2 + data.size  // type + length field + data
        return byteArrayOf(
            0x18.toByte(),                // Heartbeat record type
            0x03, version.minor.toByte(), // version
            ((innerLen shr 8) and 0xFF).toByte(),
            (innerLen and 0xFF).toByte(),
            0x01,                         // heartbeat_type: request
            ((data.size shr 8) and 0xFF).toByte(),
            (data.size and 0xFF).toByte()
        ) + data
    }

    private fun containsMarker(haystack: ByteArray, needle: ByteArray): Boolean {
        if (needle.isEmpty() || haystack.size < needle.size) return false
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) {
                if (haystack[i + j] != needle[j]) continue@outer
            }
            return true
        }
        return false
    }
}
