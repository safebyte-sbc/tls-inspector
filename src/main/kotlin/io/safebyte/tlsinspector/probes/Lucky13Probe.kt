package io.safebyte.tlsinspector.probes

import io.safebyte.tlsinspector.CipherFlag
import io.safebyte.tlsinspector.ProbeContext
import io.safebyte.tlsinspector.ProtocolStatus
import io.safebyte.tlsinspector.TlsConfidence
import io.safebyte.tlsinspector.TlsProtocol
import io.safebyte.tlsinspector.TlsScanResult
import io.safebyte.tlsinspector.TlsSeverity
import io.safebyte.tlsinspector.reporting.TlsFinding

/**
 * Lucky13 (CVE-2013-0169) probe.
 *
 * Lucky13 is a timing side-channel attack against CBC cipher suites in TLS 1.0,
 * 1.1, and 1.2. The attack exploits a timing difference in how the MAC computation
 * varies depending on the padding length, allowing an attacker to recover plaintext
 * via a padding oracle. Practical exploitation requires precise timing measurement
 * capability and many thousands of connections.
 *
 * Confidence is TENTATIVE because: (1) the attack requires sub-millisecond timing
 * measurement across a network, and (2) most modern TLS libraries have constant-time
 * MAC implementations as countermeasures. Severity is LOW.
 *
 * Pure-logic check — no network I/O.
 */
class Lucky13Probe : TlsProbe {
    override val id = "LUCKY13"
    override val displayName = "Lucky13 (CVE-2013-0169)"
    override val kind = ProbeKind.VULNERABILITY

    override fun run(ctx: ProbeContext, result: TlsScanResult): List<TlsFinding> {
        return runWithResult(ctx, result).findings
    }

    override fun runWithResult(ctx: ProbeContext, result: TlsScanResult): ProbeResult {
        val started = System.currentTimeMillis()

        // Collect all CBC (non-AEAD) ciphers across TLS 1.0, 1.1, 1.2
        val affected = listOf(TlsProtocol.TLS_1_0, TlsProtocol.TLS_1_1, TlsProtocol.TLS_1_2)
            .filter { proto -> result.protocolsOffered[proto] == ProtocolStatus.OFFERED }
            .flatMap { proto ->
                val ciphers = result.ciphersByProtocol[proto] ?: emptyList()
                ciphers
                    .filter { c ->
                        c.encryption.endsWith("CBC", ignoreCase = true) &&
                        CipherFlag.AEAD !in c.flags
                    }
                    .map { c -> proto to c }
            }

        if (affected.isEmpty()) {
            return ProbeResult.notVulnerable(id, displayName, System.currentTimeMillis() - started)
        }

        val affectedListHtml = affected.joinToString("") { (p, c) ->
            "<li><code>${c.name}</code> on ${p.displayName}</li>"
        }

        val finding = TlsFinding(
            id = "LUCKY13:cbc_offered",
            title = "Lucky13: CBC Cipher Suites Offered (CVE-2013-0169)",
            severity = TlsSeverity.LOW,
            confidence = TlsConfidence.TENTATIVE,
            descriptionHtml = """
                <p><b>Summary:</b> ${affected.size} CBC (non-AEAD) cipher suite(s) offered on legacy TLS versions.</p>
                <p>Lucky13 (CVE-2013-0169) is a timing side-channel attack against TLS CBC padding
                verification. The attack exploits the fact that HMAC computation takes slightly longer
                for some padding lengths, creating a timing oracle. An attacker requires many thousands
                of connections and precise timing measurement (&lt;1ms precision) to recover plaintext.</p>
                <p>Practical exploitability is low because: most modern TLS libraries implement
                constant-time MAC verification as a countermeasure; network jitter typically masks
                the timing differences; and the attacker must be on-path.</p>
                <p><b>Affected cipher suites:</b></p>
                <ul>${affectedListHtml}</ul>
                <p><b>CVE:</b> CVE-2013-0169</p>
                <p><b>Compliance impact:</b> NIST SP 800-52r2 recommends AEAD cipher suites only.
                PCI DSS 4.0 §6.2 (risk-based remediation of non-critical vulnerabilities).</p>
            """.trimIndent(),
            remediationHtml = "<p>Prefer AEAD cipher suites (AES-GCM, AES-CCM, ChaCha20-Poly1305) " +
                "which are not affected by Lucky13. Remove CBC cipher suites where possible, " +
                "particularly on TLS 1.0/1.1 which should be disabled entirely.</p>",
            references = listOf(
                "https://nvd.nist.gov/vuln/detail/CVE-2013-0169",
                "http://www.isg.rhul.ac.uk/tls/Lucky13.html",
            )
        )
        result.findings.add(finding)
        return ProbeResult.potentiallyVulnerable(id, displayName, listOf(finding),
            System.currentTimeMillis() - started,
            "${affected.size} CBC cipher(s) across legacy TLS versions")
    }
}
