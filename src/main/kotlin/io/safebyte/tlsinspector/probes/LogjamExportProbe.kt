package io.safebyte.tlsinspector.probes

import io.safebyte.tlsinspector.HandshakeResult
import io.safebyte.tlsinspector.ProbeContext
import io.safebyte.tlsinspector.ProtocolStatus
import io.safebyte.tlsinspector.TlsConfidence
import io.safebyte.tlsinspector.TlsConnector
import io.safebyte.tlsinspector.TlsProtocol
import io.safebyte.tlsinspector.TlsScanResult
import io.safebyte.tlsinspector.TlsSeverity
import io.safebyte.tlsinspector.reporting.TlsFinding

/**
 * Logjam Export DHE (CVE-2015-4000) probe — export-grade DHE cipher acceptance.
 *
 * The Logjam attack exploits DHE_EXPORT cipher suites which use 512-bit DH primes.
 * These primes are small enough to be broken by precomputed discrete logarithm tables
 * (number field sieve), allowing a MITM attacker to downgrade DHE key exchanges and
 * recover session keys in minutes (or seconds for precomputed targets).
 *
 * This probe attempts handshakes offering only DHE_EXPORT cipher suites.
 * If the server negotiates any of them, it is VULNERABLE.
 *
 * Active probe — one TCP connection per offered TLS version.
 */
class LogjamExportProbe : TlsProbe {
    override val id = "LOGJAM_EXPORT"
    override val displayName = "Logjam Export (DHE_EXPORT)"
    override val kind = ProbeKind.VULNERABILITY

    /**
     * IANA codes for DHE_EXPORT cipher suites (all use 512-bit ephemeral DH).
     * From RFC 2246 (TLS 1.0) and TLS Cipher Suite Registry.
     */
    private val EXPORT_DHE_CIPHERS = intArrayOf(
        0x0011, // TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
        0x0014, // TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
        0x0019, // TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA
        0x000B, // TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA
        0x000E, // TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA
    )

    private val EXPORT_DHE_CIPHERS_SET: Set<Int> = EXPORT_DHE_CIPHERS.toSet()

    override fun run(ctx: ProbeContext, result: TlsScanResult): List<TlsFinding> {
        return runWithResult(ctx, result).findings
    }

    override fun runWithResult(ctx: ProbeContext, result: TlsScanResult): ProbeResult {
        val started = System.currentTimeMillis()

        val applicableProtos = listOf(TlsProtocol.TLS_1_0, TlsProtocol.TLS_1_1, TlsProtocol.TLS_1_2)
            .filter { result.protocolsOffered[it] == ProtocolStatus.OFFERED }

        if (applicableProtos.isEmpty()) {
            return ProbeResult.notApplicable(id, displayName,
                "No TLS 1.0/1.1/1.2 offered — DHE_EXPORT probe cannot run",
                System.currentTimeMillis() - started)
        }

        val connector = TlsConnector(ctx)
        for (proto in applicableProtos) {
            if (ctx.cancelled()) break
            val outcome = connector.probeHandshake(proto, EXPORT_DHE_CIPHERS)
            if (outcome is HandshakeResult.Success &&
                outcome.negotiatedCipherSuite in EXPORT_DHE_CIPHERS_SET) {

                val suiteHex = "%04X".format(outcome.negotiatedCipherSuite)
                val finding = TlsFinding(
                    id = "LOGJAM_EXPORT:dhe_export_accepted:${proto.name}",
                    title = "Logjam: Export-grade DHE Accepted (CVE-2015-4000)",
                    severity = TlsSeverity.HIGH,
                    confidence = TlsConfidence.CERTAIN,
                    descriptionHtml = """
                        <p><b>Summary:</b> The server accepted export-grade DHE cipher suite
                        <code>0x$suiteHex</code> on ${proto.displayName}.</p>
                        <p>The Logjam attack (CVE-2015-4000) exploits DHE_EXPORT cipher suites which
                        use 512-bit Diffie-Hellman primes. These small primes can be broken by a
                        precomputed number field sieve attack in minutes. A MITM attacker can intercept
                        a DHE key exchange, substitute the 512-bit export prime, solve the discrete
                        logarithm, and recover the session key — decrypting all traffic in the session.</p>
                        <p>DHE_EXPORT cipher suites were defined for US export restrictions in the 1990s
                        and have no legitimate use. They were removed from all modern TLS libraries.</p>
                        <p><b>CVE:</b> CVE-2015-4000</p>
                        <p><b>Compliance impact:</b> PCI DSS 4.0 §4.2.1 (prohibits export-grade crypto);
                        NIST SP 800-52r2 §3.3.1 (512-bit DH prohibited).</p>
                    """.trimIndent(),
                    remediationHtml = "<p>Remove all <code>DHE_EXPORT</code> and <code>DH_anon_EXPORT</code> " +
                        "cipher suites from the server configuration. For OpenSSL: use " +
                        "<code>!EXPORT</code> in the cipher string. Ensure DH parameters are " +
                        "at least 2048 bits.</p>",
                    references = listOf(
                        "https://weakdh.org/",
                        "https://nvd.nist.gov/vuln/detail/CVE-2015-4000",
                    )
                )
                result.findings.add(finding)
                return ProbeResult.vulnerable(id, displayName, listOf(finding),
                    System.currentTimeMillis() - started,
                    "DHE_EXPORT 0x$suiteHex accepted on ${proto.displayName}")
            }
        }

        return ProbeResult.notVulnerable(id, displayName, System.currentTimeMillis() - started)
    }
}
