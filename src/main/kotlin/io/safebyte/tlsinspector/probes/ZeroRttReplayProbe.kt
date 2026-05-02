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
 * TLS 1.3 0-RTT Replay Risk (RFC 8446 §8).
 *
 * TLS 1.3 0-RTT (Early Data) allows a client to send application data in the
 * first flight using a previously negotiated session ticket. If the server does
 * not enforce anti-replay measures (single-use tickets, server-side cache,
 * time window), an attacker can replay 0-RTT data.
 *
 * Detection heuristic:
 * - If TLS 1.3 is not supported → NOT_APPLICABLE
 * - Open a TLS 1.3 handshake; if the server includes the early_data extension
 *   (0x002a) or session_ticket extension (0x0029) → POTENTIALLY_VULNERABLE
 * - If TLS 1.3 completes without early_data → NOT_VULNERABLE with caveat
 *
 * Note: Full replay verification (send early data twice on same ticket) requires
 * a complete TLS 1.3 state machine — this probe is a heuristic indicator only.
 */
class ZeroRttReplayProbe : TlsProbe {
    override val id = "ZERO_RTT_REPLAY"
    override val displayName = "TLS 1.3 0-RTT Replay Risk"
    override val kind = ProbeKind.VULNERABILITY

    private val EXT_EARLY_DATA     = 0x002a
    private val EXT_SESSION_TICKET = 0x0029

    override fun run(ctx: ProbeContext, result: TlsScanResult): List<TlsFinding> =
        runWithResult(ctx, result).findings

    override fun runWithResult(ctx: ProbeContext, result: TlsScanResult): ProbeResult {
        val started = System.currentTimeMillis()

        if (result.protocolsOffered[TlsProtocol.TLS_1_3] != ProtocolStatus.OFFERED) {
            return ProbeResult.notApplicable(id, displayName,
                "TLS 1.3 not supported — 0-RTT not applicable",
                System.currentTimeMillis() - started)
        }

        return try {
            probeZeroRtt(ctx, result, started)
        } catch (e: Exception) {
            ProbeResult.error(id, displayName,
                "0-RTT probe error: ${e.javaClass.simpleName}: ${e.message}",
                System.currentTimeMillis() - started)
        }
    }

    private fun probeZeroRtt(ctx: ProbeContext, result: TlsScanResult, started: Long): ProbeResult {
        val timeoutMs = ctx.budget.handshakeTimeout.toMillis().toInt()
        val sock = TlsRawSocket.openSocket(ctx)
        return sock.use {
            // TLS 1.3 ClientHello — use TLS_1_3 version to trigger supported_versions extension
            val hello = ClientHelloBuilder.build(
                version = TlsProtocol.TLS_1_3,
                sni = ctx.sni,
                cipherSuites = ClientHelloBuilder.DEFAULT_CIPHER_SUITES,
            )
            sock.getOutputStream().write(hello)
            sock.getOutputStream().flush()

            val (rawBuf, _) = TlsRawSocket.readUntilServerHelloDone(sock, timeoutMs)

            val hasEarlyData     = containsExtension(rawBuf, EXT_EARLY_DATA)
            val hasSessionTicket = containsExtension(rawBuf, EXT_SESSION_TICKET)

            when {
                hasEarlyData -> {
                    val finding = TlsFinding(
                        id = "ZERO_RTT_REPLAY:early_data_extension",
                        title = "TLS 1.3 0-RTT: Server Advertises early_data Extension",
                        severity = TlsSeverity.MEDIUM,
                        confidence = TlsConfidence.TENTATIVE,
                        descriptionHtml = """
                            <p><b>Summary:</b> The server advertises the <code>early_data</code>
                            extension (0x002a) in its TLS 1.3 handshake, indicating 0-RTT is offered.
                            Replay protection was not verified at this tool's level.</p>
                            <p>TLS 1.3 0-RTT (Early Data, RFC 8446 §8) allows a client to send data
                            in the first flight using a previously negotiated session ticket. If the
                            server lacks anti-replay measures (single-use tickets, server-side cache,
                            time-window validation), an attacker with a copy of the 0-RTT ciphertext
                            can replay it to the server — causing repeated execution of non-idempotent
                            actions (e.g. financial transactions, authentication tokens).</p>
                            <p><b>RFC:</b> RFC 8446 §8 (0-RTT and Anti-Replay)</p>
                            <p><b>Compliance:</b> NIST SP 800-52r2 §3.5 (consider disabling 0-RTT
                            for high-value endpoints).</p>
                        """.trimIndent(),
                        remediationHtml = "<p>Disable 0-RTT / early data entirely for high-value endpoints. " +
                            "If 0-RTT is required for performance, enforce server-side anti-replay via " +
                            "single-use session tickets, a replay cache, or time-window validation. " +
                            "RFC 8446 §8.1 describes the required anti-replay mechanisms.</p>",
                        references = listOf(
                            "https://tools.ietf.org/html/rfc8446#section-8",
                            "https://blog.cloudflare.com/introducing-0-rtt/",
                        )
                    )
                    synchronized(result) { result.findings.add(finding) }
                    ProbeResult.potentiallyVulnerable(id, displayName, listOf(finding),
                        System.currentTimeMillis() - started,
                        "early_data extension (0x002a) present in TLS 1.3 handshake")
                }
                hasSessionTicket -> {
                    val finding = TlsFinding(
                        id = "ZERO_RTT_REPLAY:session_ticket_offered",
                        title = "TLS 1.3 0-RTT: Session Ticket Offered (Replay Risk Unverified)",
                        severity = TlsSeverity.LOW,
                        confidence = TlsConfidence.TENTATIVE,
                        descriptionHtml = """
                            <p><b>Summary:</b> The server offers a TLS 1.3 session ticket
                            (extension 0x0029). 0-RTT resumption may be enabled; replay protection
                            was not verified at this tool's level.</p>
                            <p>Session tickets enable 0-RTT resumption which may be susceptible to
                            replay attacks if anti-replay measures are not implemented server-side.
                            RFC 8446 §8 describes the required protections.</p>
                        """.trimIndent(),
                        remediationHtml = "<p>Verify 0-RTT is disabled or that anti-replay is enforced. " +
                            "RFC 8446 §8.1 requires server-side anti-replay for 0-RTT deployments.</p>",
                        references = listOf("https://tools.ietf.org/html/rfc8446#section-8")
                    )
                    synchronized(result) { result.findings.add(finding) }
                    ProbeResult.potentiallyVulnerable(id, displayName, listOf(finding),
                        System.currentTimeMillis() - started,
                        "TLS 1.3 session ticket (0x0029) present — 0-RTT replay unverified")
                }
                rawBuf.isNotEmpty() ->
                    ProbeResult.notVulnerable(id, displayName, System.currentTimeMillis() - started)
                else ->
                    ProbeResult.error(id, displayName,
                        "TLS 1.3 handshake produced no data",
                        System.currentTimeMillis() - started)
            }
        }
    }

    /**
     * Scan raw TLS records for a specific extension type value in any handshake message payload.
     * Best-effort byte scan — not a full TLS extension parser.
     */
    private fun containsExtension(raw: ByteArray, extType: Int): Boolean {
        val hi = ((extType shr 8) and 0xFF).toByte()
        val lo = (extType and 0xFF).toByte()
        for (i in 0 until raw.size - 1) {
            if (raw[i] == hi && raw[i + 1] == lo) return true
        }
        return false
    }
}
