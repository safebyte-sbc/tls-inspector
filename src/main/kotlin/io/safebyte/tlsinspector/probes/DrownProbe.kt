package io.safebyte.tlsinspector.probes

import io.safebyte.tlsinspector.ProbeContext
import io.safebyte.tlsinspector.ProtocolStatus
import io.safebyte.tlsinspector.TlsConfidence
import io.safebyte.tlsinspector.TlsProtocol
import io.safebyte.tlsinspector.TlsScanResult
import io.safebyte.tlsinspector.TlsSeverity
import io.safebyte.tlsinspector.reporting.TlsFinding

/**
 * DROWN (CVE-2016-0800) probe.
 *
 * DROWN (Decrypting RSA with Obsolete and Weakened eNcryption) allows an attacker
 * who can make SSLv2 connections to the server to decrypt modern TLS traffic captured
 * elsewhere — even if the victim uses TLS 1.2 — by leveraging the shared private key.
 *
 * Pure-logic check: if SSLv2 is OFFERED, the server is vulnerable.
 * Depends on ProtocolEnumerationProbe having run first.
 */
class DrownProbe : TlsProbe {
    override val id = "DROWN"
    override val displayName = "DROWN (CVE-2016-0800)"
    override val kind = ProbeKind.VULNERABILITY

    override fun run(ctx: ProbeContext, result: TlsScanResult): List<TlsFinding> {
        return runWithResult(ctx, result).findings
    }

    override fun runWithResult(ctx: ProbeContext, result: TlsScanResult): ProbeResult {
        val started = System.currentTimeMillis()

        if (result.protocolsOffered[TlsProtocol.SSL_2_0] != ProtocolStatus.OFFERED) {
            return ProbeResult.notVulnerable(id, displayName, System.currentTimeMillis() - started)
        }

        val finding = TlsFinding(
            id = "DROWN:sslv2_offered",
            title = "DROWN: SSLv2 Supported (CVE-2016-0800)",
            severity = TlsSeverity.HIGH,
            confidence = TlsConfidence.CERTAIN,
            descriptionHtml = """
                <p><b>Summary:</b> The server accepts SSLv2 connections.</p>
                <p>DROWN (CVE-2016-0800) allows a network attacker to decrypt modern TLS sessions
                (including TLS 1.2) by exploiting SSLv2 export-grade cryptography weaknesses. If the
                SSLv2 service shares its RSA private key with a TLS service — which is the default
                for most server configurations — all TLS traffic encrypted with that key can be
                decrypted offline using approximately 40,000 SSLv2 probes per target session.</p>
                <p>The SSLv2 protocol was officially deprecated by RFC 6176 (2011) and has no
                legitimate use in any modern deployment.</p>
                <p><b>CVE:</b> CVE-2016-0800</p>
                <p><b>Compliance impact:</b> PCI DSS 4.0 §4.2.1 (prohibits SSLv2/SSLv3); TLS 1.2
                minimum required. BNM/HCE guidelines require TLS 1.2+.</p>
            """.trimIndent(),
            remediationHtml = "<p>Disable SSLv2 completely on the server and any load balancers " +
                "or proxies that share the same RSA private key. Minimum supported protocol " +
                "must be TLS 1.2.</p>",
            references = listOf(
                "https://drownattack.com/",
                "https://nvd.nist.gov/vuln/detail/CVE-2016-0800",
                "https://tools.ietf.org/html/rfc6176",
            )
        )
        result.findings.add(finding)
        return ProbeResult.vulnerable(id, displayName, listOf(finding),
            System.currentTimeMillis() - started,
            "SSLv2 accepted")
    }
}
