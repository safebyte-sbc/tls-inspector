package io.safebyte.tlsinspector.certificate

import io.safebyte.tlsinspector.TlsConfidence
import io.safebyte.tlsinspector.TlsSeverity
import io.safebyte.tlsinspector.reporting.TlsFinding

object CertificateAnomalyDetector {

    private val INTERNAL_TLD_SUFFIXES = listOf(".local", ".lan", ".internal", ".corp", ".intra", ".test", ".localhost")
    private val WEAK_HASH_ALGORITHMS = setOf("MD5", "SHA-1")
    private const val MAX_VALIDITY_DAYS = 825L
    private const val EXPIRING_SOON_DAYS = 30L

    fun detect(cert: ParsedCertificate, host: String): List<TlsFinding> {
        val out = mutableListOf<TlsFinding>()

        // 1. Expired
        if (cert.isExpired) out += finding(
            "CERT_ANOMALY:expired",
            "TLS Certificate is Expired",
            TlsSeverity.CRITICAL,
            "<p>The leaf certificate expired ${-cert.daysToExpiry} days ago (notAfter = ${cert.notAfter}).</p>",
            references = listOf("https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.5")
        )

        // 2. Expiring soon
        if (!cert.isExpired && cert.daysToExpiry < EXPIRING_SOON_DAYS) out += finding(
            "CERT_ANOMALY:expiring_soon",
            "TLS Certificate Expiring in ${cert.daysToExpiry} Days",
            TlsSeverity.MEDIUM,
            "<p>Certificate expires on ${cert.notAfter} (${cert.daysToExpiry} days remaining).</p>"
        )

        // 3. Not yet valid
        if (cert.isNotYetValid) out += finding(
            "CERT_ANOMALY:not_yet_valid",
            "TLS Certificate is Not Yet Valid",
            TlsSeverity.HIGH,
            "<p>Certificate notBefore = ${cert.notBefore} is in the future. Server clock may be wrong, or the certificate was issued for future use.</p>"
        )

        // 4. Self-signed leaf in production (skip for internal domains)
        if (cert.isSelfSigned && !isInternalDomain(host)) out += finding(
            "CERT_ANOMALY:self_signed",
            "Self-Signed Certificate on Public Hostname",
            TlsSeverity.HIGH,
            "<p>Leaf certificate is self-signed. Public hostnames must use a chain rooted at a trusted CA.</p>"
        )

        // 5. Weak signature
        val hash = cert.signatureAlgorithm.hashAlgorithm
        if (hash in WEAK_HASH_ALGORITHMS) out += finding(
            "CERT_ANOMALY:weak_signature_$hash",
            "Weak Signature Algorithm: $hash",
            TlsSeverity.HIGH,
            "<p>Certificate is signed using <code>${cert.signatureAlgorithm.name}</code> ($hash). $hash is collision-vulnerable and deprecated by all modern browsers.</p>"
        )

        // 6. Weak key
        when (cert.publicKey.algorithm) {
            "RSA" -> if (cert.publicKey.sizeBits < 2048) out += finding(
                "CERT_ANOMALY:weak_rsa_key",
                "Weak RSA Public Key (${cert.publicKey.sizeBits} bits)",
                TlsSeverity.HIGH,
                "<p>RSA modulus is only ${cert.publicKey.sizeBits} bits. Modern requirement is ≥2048.</p>"
            )
            "EC" -> if (cert.publicKey.sizeBits < 256) out += finding(
                "CERT_ANOMALY:weak_ec_key",
                "Weak EC Curve (${cert.publicKey.curveName ?: "unknown"})",
                TlsSeverity.HIGH,
                "<p>EC curve ${cert.publicKey.curveName} provides only ${cert.publicKey.sizeBits} bits of security.</p>"
            )
        }

        // 7. Hostname mismatch / CN-only legacy match
        val match = HostnameMatcher.matches(host, cert)
        if (match is HostnameMatcher.MatchResult.NoMatch) out += finding(
            "CERT_ANOMALY:hostname_mismatch",
            "TLS Certificate Hostname Mismatch",
            TlsSeverity.HIGH,
            "<p>Target host <code>$host</code> does not match any SAN or CN. ${match.reason}.</p><p>SANs:</p><ul>${
                cert.subjectAlternativeNames.joinToString("") { "<li>${it.type}: <code>${it.value}</code></li>" }
            }</ul>"
        )

        // 8. CN-only legacy match
        if (match is HostnameMatcher.MatchResult.Match.LegacyCommonName) out += finding(
            "CERT_ANOMALY:cn_only_legacy_match",
            "CN-Only Match (No DNS SAN)",
            TlsSeverity.MEDIUM,
            "<p>Certificate matched via Common Name fallback. Modern browsers reject CN-only matching (RFC 2818 deprecated, RFC 6125 requires SAN).</p>"
        )

        // 9. Wildcard scope classification — BROAD and DANGEROUS wildcards are flagged
        cert.subjectAlternativeNames.filter { it.type == SanType.DNS && it.value.startsWith("*.") }.forEach { san ->
            when (HostnameMatcher.classifyWildcardScope(san.value)) {
                HostnameMatcher.WildcardScope.DANGEROUS -> out += finding(
                    "CERT_WILDCARD_DANGEROUS:${san.value}",
                    "Wildcard SAN at TLD/Public Suffix Level: ${san.value}",
                    TlsSeverity.HIGH,
                    "<p>SAN <code>${san.value}</code> is a TLD or public-suffix wildcard. " +
                        "It would match every subdomain of a public suffix, effectively covering domains across organizations.</p>"
                )
                HostnameMatcher.WildcardScope.BROAD -> out += finding(
                    "CERT_WILDCARD_BROAD:${san.value}",
                    "Broad Wildcard SAN: ${san.value}",
                    TlsSeverity.LOW,
                    "<p>SAN <code>${san.value}</code> is a single-level wildcard covering all subdomains of the domain. " +
                        "While common, broad wildcards increase the blast radius if the certificate's private key is compromised.</p>"
                )
                else -> { /* NARROW or NOT_WILDCARD — no finding */ }
            }
        }

        // 10. Excessive validity
        if (cert.validityDays > MAX_VALIDITY_DAYS) out += finding(
            "CERT_ANOMALY:excessive_validity",
            "Excessive Certificate Validity Period",
            TlsSeverity.LOW,
            "<p>Validity period is ${cert.validityDays} days, exceeds CA/B Forum 2020 limit of $MAX_VALIDITY_DAYS days.</p>"
        )

        // 11. Unknown critical extensions
        if (cert.unknownCriticalExtensions.isNotEmpty()) out += finding(
            "CERT_ANOMALY:unknown_critical_extension",
            "Unknown Critical X.509 Extension",
            TlsSeverity.LOW,
            "<p>Certificate contains critical extensions not recognized by the analyzer: <code>${cert.unknownCriticalExtensions.joinToString(", ")}</code>.</p>"
        )

        return out
    }

    private fun isInternalDomain(host: String): Boolean {
        val h = host.lowercase()
        return INTERNAL_TLD_SUFFIXES.any { h.endsWith(it) } || h.matches(Regex("""^[\d.]+$"""))
    }

    private fun finding(
        id: String, title: String, severity: TlsSeverity, descriptionHtml: String,
        references: List<String> = emptyList()
    ) = TlsFinding(
        id = id, title = title, severity = severity, confidence = TlsConfidence.FIRM,
        descriptionHtml = descriptionHtml, references = references
    )
}
