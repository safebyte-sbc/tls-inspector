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
import io.safebyte.tlsinspector.WeakDhPrimes
import io.safebyte.tlsinspector.reporting.TlsFinding

/**
 * Logjam Common Prime (CVE-2015-4000) probe — weak/shared DH prime detection.
 *
 * Even when servers use full-strength DHE (not export-grade), they may still use
 * well-known "common primes" — DH primes reused across thousands of servers (e.g.
 * RFC 2409 Group 2, the historical IPSec/IKE 1024-bit MODP prime). Attackers can
 * precompute discrete logarithm tables for a specific prime once (~$100M in 2015,
 * $1M in 2020) and then break any DHE session using that prime in seconds.
 *
 * This probe:
 *  1. Sends a DHE-only ClientHello using a raw socket
 *  2. Parses the DH prime from the ServerKeyExchange
 *  3. Checks the prime against the WeakDhPrimes catalog (known weak/shared primes)
 *  4. Also checks the bit length (< 1024 = HIGH, == 1024 = MEDIUM, < 2048 = LOW)
 *
 * Active probe — one TCP connection.
 */
class LogjamCommonPrimeProbe : TlsProbe {
    override val id = "LOGJAM_COMMON_PRIME"
    override val displayName = "Logjam (Common 1024-bit DH Prime)"
    override val kind = ProbeKind.VULNERABILITY

    /**
     * DHE cipher suite codes (non-export, standard strength).
     * We advertise these to force the server into a DHE key exchange.
     */
    private val DHE_CIPHERS = intArrayOf(
        0x0033, // TLS_DHE_RSA_WITH_AES_128_CBC_SHA
        0x0039, // TLS_DHE_RSA_WITH_AES_256_CBC_SHA
        0x0067, // TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
        0x006B, // TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
        0x009E, // TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
        0x009F, // TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
        0x00A2, // TLS_DHE_DSS_WITH_AES_128_GCM_SHA256
        0x00A3, // TLS_DHE_DSS_WITH_AES_256_GCM_SHA384
        0x0032, // TLS_DHE_DSS_WITH_AES_128_CBC_SHA
        0x0038, // TLS_DHE_DSS_WITH_AES_256_CBC_SHA
        0x0040, // TLS_DHE_DSS_WITH_AES_128_CBC_SHA256
        0x006A, // TLS_DHE_DSS_WITH_AES_256_CBC_SHA256
    )

    override fun run(ctx: ProbeContext, result: TlsScanResult): List<TlsFinding> {
        return runWithResult(ctx, result).findings
    }

    override fun runWithResult(ctx: ProbeContext, result: TlsScanResult): ProbeResult {
        val started = System.currentTimeMillis()

        // Pick the highest offered TLS 1.0/1.1/1.2 protocol
        val proto = listOf(TlsProtocol.TLS_1_2, TlsProtocol.TLS_1_1, TlsProtocol.TLS_1_0)
            .firstOrNull { result.protocolsOffered[it] == ProtocolStatus.OFFERED }
            ?: return ProbeResult.notApplicable(id, displayName,
                "No TLS 1.0/1.1/1.2 offered — DHE common prime probe cannot run",
                System.currentTimeMillis() - started)

        // Build a ClientHello advertising DHE-only ciphers via raw socket
        // We use probeRawAfterHello to get raw bytes including the ServerKeyExchange
        val clientHello = ClientHelloBuilder.build(
            version = proto,
            sni = ctx.sni,
            cipherSuites = DHE_CIPHERS.toList(),
        )

        val outcome = TlsConnector(ctx).probeRawAfterHello(clientHello, ByteArray(0))
        if (outcome is RawProbeOutcome.Error) {
            return ProbeResult.error(id, displayName,
                "I/O error: ${outcome.message}",
                System.currentTimeMillis() - started)
        }

        val ok = outcome as RawProbeOutcome.Ok

        // Extract the DH prime from the ServerKeyExchange
        val dh = HandshakeParser.extractDhPrimeFromServerKeyExchange(ok.handshakePhase)
            ?: return ProbeResult.notApplicable(id, displayName,
                "Server did not negotiate DHE — no ServerKeyExchange found",
                System.currentTimeMillis() - started)

        // Check catalog of known weak/shared primes
        val knownEntry = WeakDhPrimes.lookup(dh.sha256Hex)

        val (severity, confidence, title, detail) = when {
            knownEntry != null -> Quad(
                TlsSeverity.HIGH,
                TlsConfidence.CERTAIN,
                "Logjam: Well-Known Weak DH Prime (${knownEntry.label})",
                "<p>The server is using a well-known shared DH prime: <b>${knownEntry.label}</b> " +
                "(${dh.sizeBits}-bit). This prime is used by thousands of servers, making it a " +
                "high-value precomputation target. An attacker with access to precomputed " +
                "discrete logarithm tables for this prime can break the DHE key exchange in " +
                "real time. Reference: <a href=\"${knownEntry.source}\">${knownEntry.source}</a></p>"
            )
            dh.sizeBits < 1024 -> Quad(
                TlsSeverity.HIGH,
                TlsConfidence.CERTAIN,
                "Logjam: DH Prime Below 1024 Bits (${dh.sizeBits} bits)",
                "<p>The server is using a ${dh.sizeBits}-bit DH prime, which is below the minimum " +
                "recommended size of 1024 bits. Primes of this size can be broken by a well-resourced " +
                "attacker in hours using the number field sieve.</p>"
            )
            dh.sizeBits == 1024 -> Quad(
                TlsSeverity.MEDIUM,
                TlsConfidence.CERTAIN,
                "Logjam: 1024-bit DH Prime Used",
                "<p>The server is using a 1024-bit DH prime. While not immediately breakable by " +
                "most attackers, 1024-bit primes are considered at risk from nation-state adversaries " +
                "who may have precomputed discrete logarithm tables. NIST SP 800-131A (2019) prohibits " +
                "1024-bit DH parameters.</p>"
            )
            dh.sizeBits < 2048 -> Quad(
                TlsSeverity.LOW,
                TlsConfidence.CERTAIN,
                "Logjam: DH Prime Below 2048 Bits (${dh.sizeBits} bits)",
                "<p>The server is using a ${dh.sizeBits}-bit DH prime, which is below the recommended " +
                "minimum of 2048 bits. NIST SP 800-57 and ENISA recommend at least 2048-bit DH " +
                "parameters for all new deployments.</p>"
            )
            else -> return ProbeResult.notVulnerable(id, displayName, System.currentTimeMillis() - started)
        }

        val primeHexShort = if (dh.primeHex.length > 32) dh.primeHex.take(32) + "…" else dh.primeHex

        val finding = TlsFinding(
            id = "LOGJAM_COMMON_PRIME:${dh.sizeBits}bit${if (knownEntry != null) ":known" else ""}",
            title = title,
            severity = severity,
            confidence = confidence,
            descriptionHtml = """
                <p><b>Summary:</b> DH prime: ${dh.sizeBits} bits, SHA-256: <code>${dh.sha256Hex.take(16)}…</code>,
                hex prefix: <code>$primeHexShort</code></p>
                $detail
                <p>The Logjam attack (CVE-2015-4000) demonstrates that precomputed NFS attacks against
                fixed DH primes allow passive decryption of DHE sessions. This affects any two parties
                using DHE with the same prime.</p>
                <p><b>CVE:</b> CVE-2015-4000</p>
                <p><b>Compliance impact:</b> PCI DSS 4.0 §4.2.1; NIST SP 800-131A Rev. 2 (2019)
                prohibits DH parameters below 2048 bits after 2013.</p>
            """.trimIndent(),
            remediationHtml = "<p>Generate fresh, unique DH parameters of at least 2048 bits: " +
                "<code>openssl dhparam -out dhparams.pem 2048</code>. " +
                "Prefer ECDHE (e.g. secp256r1, x25519) which provides better performance and " +
                "eliminates the shared-prime problem entirely.</p>",
            references = listOf(
                "https://weakdh.org/",
                "https://nvd.nist.gov/vuln/detail/CVE-2015-4000",
            )
        )
        result.findings.add(finding)

        return if (knownEntry != null || dh.sizeBits < 1024 || dh.sizeBits == 1024) {
            ProbeResult.vulnerable(id, displayName, listOf(finding),
                System.currentTimeMillis() - started,
                "DH prime ${dh.sizeBits} bits${if (knownEntry != null) " (${knownEntry.label})" else ""}")
        } else {
            ProbeResult.potentiallyVulnerable(id, displayName, listOf(finding),
                System.currentTimeMillis() - started,
                "DH prime ${dh.sizeBits} bits (below 2048-bit recommendation)")
        }
    }

    /** Simple 4-tuple for destructuring — avoids a data class import. */
    private data class Quad(
        val severity: TlsSeverity,
        val confidence: TlsConfidence,
        val title: String,
        val detail: String,
    )
}
