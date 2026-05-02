package io.safebyte.tlsinspector.probes

import io.safebyte.tlsinspector.PqcGroups
import io.safebyte.tlsinspector.PqcProbeOutcome
import io.safebyte.tlsinspector.ProbeContext
import io.safebyte.tlsinspector.ProtocolStatus
import io.safebyte.tlsinspector.TlsConfidence
import io.safebyte.tlsinspector.TlsConnector
import io.safebyte.tlsinspector.TlsProtocol
import io.safebyte.tlsinspector.TlsScanResult
import io.safebyte.tlsinspector.TlsSeverity
import io.safebyte.tlsinspector.reporting.TlsFinding

/**
 * PQC Hybrid KEM Probe (MS E).
 *
 * Detects whether the server supports post-quantum hybrid key encapsulation mechanisms
 * as defined in draft-ietf-tls-ecdhe-mlkem. Currently deployed by Google, Cloudflare,
 * and required for future NIST PQC migration baselines.
 *
 * Probe strategy:
 *   Probe A — Offer only PQC groups (X25519MLKEM768, X25519Kyber768Draft00, SecP256r1MLKEM768)
 *              with classical-only key_share entries. A HelloRetryRequest means the server
 *              recognised at least one PQC group but wants a key share for it.
 *   Probe B — (only if A shows PQC support) Offer mixed PQC+classical. Observe which group
 *              the server selects to determine preference.
 *
 * Verdict:
 *   PQC supported + PQC preferred   → NOT_VULNERABLE (best posture)
 *   PQC supported + classical preferred → POTENTIALLY_VULNERABLE (info: PQC supported but not default)
 *   TLS 1.3 offered but no PQC      → POTENTIALLY_VULNERABLE (LOW: no PQC forward secrecy)
 *   TLS 1.3 not offered             → NOT_APPLICABLE
 */
class PqcKemProbe : TlsProbe {
    override val id = "PQC_KEM"
    override val displayName = "Post-Quantum Hybrid KEM Support"
    override val kind = ProbeKind.VULNERABILITY

    override fun run(ctx: ProbeContext, result: TlsScanResult): List<TlsFinding> =
        runWithResult(ctx, result).findings

    override fun runWithResult(ctx: ProbeContext, result: TlsScanResult): ProbeResult {
        val started = System.currentTimeMillis()
        val elapsed = { System.currentTimeMillis() - started }

        // Pre-check: TLS 1.3 must be offered — if not, this probe is not applicable
        val tls13Status = synchronized(result) { result.protocolsOffered[TlsProtocol.TLS_1_3] }
        if (tls13Status != ProtocolStatus.OFFERED) {
            return ProbeResult.notApplicable(id, displayName,
                "TLS 1.3 not offered — PQC KEM requires TLS 1.3", elapsed())
        }

        if (ctx.cancelled()) {
            return ProbeResult.notApplicable(id, displayName, "cancelled", elapsed())
        }

        val connector = TlsConnector(ctx)

        // Probe A: offer only PQC groups with classical key_share only
        // Server must HRR if it wants a PQC key share
        val probeAGroups = PqcGroups.ALL_PQC + PqcGroups.CLASSICAL
        val outcomeA = try {
            connector.probePqcSupportedGroups(probeAGroups, classicalKeyShareOnly = true)
        } catch (e: Exception) {
            PqcProbeOutcome.IoError(e.message ?: e.javaClass.simpleName)
        }

        val pqcSupportedGroup = when (outcomeA) {
            is PqcProbeOutcome.HelloRetryRequest -> outcomeA.selectedGroup
            is PqcProbeOutcome.ServerHelloKeyShare -> outcomeA.selectedGroup
            else -> null
        }
        val pqcIsSupported = pqcSupportedGroup != null && pqcSupportedGroup in PqcGroups.ALL_PQC

        if (ctx.cancelled()) {
            return ProbeResult.notApplicable(id, displayName, "cancelled", elapsed())
        }

        // Probe B: if PQC was selected in A, check classical-preference behaviour
        var pqcIsPreferred = false
        if (pqcIsSupported) {
            val probeBGroups = PqcGroups.CLASSICAL + PqcGroups.ALL_PQC  // classical first
            val outcomeB = try {
                connector.probePqcSupportedGroups(probeBGroups, classicalKeyShareOnly = false)
            } catch (e: Exception) {
                PqcProbeOutcome.IoError(e.message ?: e.javaClass.simpleName)
            }
            val bGroup = when (outcomeB) {
                is PqcProbeOutcome.HelloRetryRequest  -> outcomeB.selectedGroup
                is PqcProbeOutcome.ServerHelloKeyShare -> outcomeB.selectedGroup
                else -> null
            }
            pqcIsPreferred = bGroup != null && bGroup in PqcGroups.ALL_PQC
        }

        return buildResult(
            pqcIsSupported = pqcIsSupported,
            pqcIsPreferred = pqcIsPreferred,
            selectedGroup = pqcSupportedGroup,
            probeAOutcome = outcomeA,
            elapsedFn = elapsed,
        )
    }

    private fun buildResult(
        pqcIsSupported: Boolean,
        pqcIsPreferred: Boolean,
        selectedGroup: Int?,
        probeAOutcome: PqcProbeOutcome,
        elapsedFn: () -> Long,
    ): ProbeResult {
        val groupName = selectedGroup?.let { groupCodeToName(it) } ?: "unknown"
        val refs = listOf(
            "https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/",
            "https://blog.cloudflare.com/post-quantum-for-all/",
            "https://security.googleblog.com/2023/08/hybrid-post-quantum-tls-in-chrome-116.html",
        )

        return when {
            pqcIsSupported && pqcIsPreferred -> {
                // Best posture: PQC is supported and preferred
                ProbeResult.notVulnerable(id, displayName, elapsedFn())
            }

            pqcIsSupported && !pqcIsPreferred -> {
                // PQC supported but server prefers classical in a mixed offer
                val finding = TlsFinding(
                    id = "PQC_KEM:PQC_SUPPORTED_NOT_PREFERRED",
                    title = "Post-Quantum Hybrid KEM Supported but Not Preferred",
                    severity = TlsSeverity.INFO,
                    confidence = TlsConfidence.FIRM,
                    descriptionHtml = """
                        <p>The server supports the post-quantum hybrid KEM group
                        <b>$groupName</b> (IANA code 0x${selectedGroup?.toString(16)?.uppercase()})
                        as defined in <b>draft-ietf-tls-ecdhe-mlkem</b>. However, when offered
                        a mixed list of classical and PQC groups, the server selected a classical
                        group, indicating PQC is not its default preference.</p>
                        <p>This is an informational finding. The server is on the migration path
                        but has not yet enabled PQC-preferred mode. Clients negotiating PQC
                        explicitly will still benefit from quantum-resistant key exchange.</p>
                        <p><b>Probe outcome:</b> ${probeAOutcome::class.simpleName} &mdash; group $groupName</p>
                    """.trimIndent(),
                    remediationHtml = """
                        <p>Configure the TLS server to prefer PQC hybrid groups
                        (e.g., <code>X25519MLKEM768</code>) over classical groups in the
                        supported_groups ordering. For OpenSSL 3.2+: set
                        <code>Groups = X25519MLKEM768:prime256v1:X25519</code> in
                        <code>openssl.cnf</code>. For nginx: use
                        <code>ssl_ecdh_curve X25519MLKEM768:prime256v1:x25519;</code>.</p>
                    """.trimIndent(),
                    references = refs,
                )
                ProbeResult.potentiallyVulnerable(id, displayName, listOf(finding), elapsedFn(),
                    "PQC supported ($groupName) but classical preferred in mixed offer")
            }

            else -> {
                // TLS 1.3 offered but no PQC KEM support
                val outcomeDesc = when (probeAOutcome) {
                    is PqcProbeOutcome.AlertReceived ->
                        "Server rejected PQC groups with alert code ${probeAOutcome.description}"
                    is PqcProbeOutcome.HelloRetryRequest ->
                        "Server HRR selected classical group (code 0x${probeAOutcome.selectedGroup.toString(16).uppercase()})"
                    is PqcProbeOutcome.ServerHelloKeyShare ->
                        "Server selected classical group (code 0x${probeAOutcome.selectedGroup.toString(16).uppercase()})"
                    is PqcProbeOutcome.IoError -> "Probe error: ${probeAOutcome.reason}"
                    PqcProbeOutcome.NoResponse -> "No response received"
                }
                val finding = TlsFinding(
                    id = "PQC_KEM:PQC_NOT_SUPPORTED",
                    title = "Post-Quantum Hybrid KEM Not Supported",
                    severity = TlsSeverity.LOW,
                    confidence = TlsConfidence.FIRM,
                    descriptionHtml = """
                        <p>The server supports TLS 1.3 but does not advertise support for any
                        post-quantum hybrid KEM group as defined in
                        <b>draft-ietf-tls-ecdhe-mlkem</b> (X25519MLKEM768, X25519Kyber768Draft00,
                        SecP256r1MLKEM768).</p>
                        <p>Current TLS key exchange (ECDHE with classical groups) is vulnerable
                        to <b>harvest-now-decrypt-later</b> attacks by a sufficiently advanced
                        quantum computer. While no such computer exists today, long-lived
                        sensitive data encrypted today may be decrypted in future.</p>
                        <p>NIST selected ML-KEM (CRYSTALS-Kyber) in August 2024. PCI DSS 4.0
                        and ENISA TLS guidelines are expected to mandate PQC migration before 2030.</p>
                        <p><b>Probe outcome:</b> $outcomeDesc</p>
                    """.trimIndent(),
                    remediationHtml = """
                        <p>Enable PQC hybrid key exchange on the TLS server:</p>
                        <ul>
                        <li><b>OpenSSL 3.3+:</b> <code>Groups = X25519MLKEM768:prime256v1:X25519</code></li>
                        <li><b>nginx 1.27.x+:</b> <code>ssl_ecdh_curve X25519MLKEM768:prime256v1:x25519;</code></li>
                        <li><b>BoringSSL (Cloudflare/Google):</b> already default since 2023</li>
                        <li><b>Go 1.23+:</b> X25519MLKEM768 is enabled by default via <code>crypto/tls</code></li>
                        </ul>
                        <p>Hybrid groups provide backward compatibility: if neither peer supports
                        PQC, the handshake falls back to the classical component transparently.</p>
                    """.trimIndent(),
                    references = refs,
                )
                ProbeResult.potentiallyVulnerable(id, displayName, listOf(finding), elapsedFn(),
                    "No PQC hybrid KEM support detected")
            }
        }
    }

    private fun groupCodeToName(code: Int): String = when (code) {
        PqcGroups.X25519MLKEM768      -> "X25519MLKEM768"
        PqcGroups.X25519Kyber768Draft -> "X25519Kyber768Draft00"
        PqcGroups.SecP256r1MLKEM768   -> "SecP256r1MLKEM768"
        0x001D -> "X25519"
        0x0017 -> "secp256r1 (P-256)"
        0x0018 -> "secp384r1 (P-384)"
        0x0019 -> "secp521r1 (P-521)"
        else   -> "0x${code.toString(16).uppercase().padStart(4, '0')}"
    }
}
