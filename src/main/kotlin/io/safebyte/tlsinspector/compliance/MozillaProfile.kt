package io.safebyte.tlsinspector.compliance

import io.safebyte.tlsinspector.CipherFlag
import io.safebyte.tlsinspector.ProtocolStatus
import io.safebyte.tlsinspector.TlsProtocol
import io.safebyte.tlsinspector.TlsSeverity

/**
 * Mozilla SSL Configuration Generator profiles:
 *   - Old      — broadest compatibility (TLS 1.0+), for legacy clients
 *   - Intermediate — recommended for most servers (TLS 1.2+)
 *   - Modern   — TLS 1.3 only, highest security
 *
 * Reference: https://wiki.mozilla.org/Security/Server_Side_TLS
 * Version:   5.7 (2023-08)
 */
object MozillaProfile {

    private fun offeredProtocols(r: io.safebyte.tlsinspector.TlsScanResult) =
        r.protocolsOffered.filterValues { it == ProtocolStatus.OFFERED }.keys

    // ─── MODERN ───────────────────────────────────────────────────────────

    val MODERN: CompliancePolicy = CompliancePolicy(
        id = "MOZILLA_MODERN",
        displayName = "Mozilla SSL — Modern",
        version = "5.7 (2023-08)",
        reference = "https://wiki.mozilla.org/Security/Server_Side_TLS",
        requirements = listOf(
            ComplianceRequirement(
                id = "MOZ_MOD_TLS13_ONLY",
                title = "Only TLS 1.3 must be offered",
                spec = "Mozilla Modern §3.1"
            ) { r ->
                val offered = offeredProtocols(r)
                val legacy = offered.filter { it != TlsProtocol.TLS_1_3 }
                if (legacy.isEmpty()) {
                    RequirementOutcome.Pass("Only TLS 1.3 offered")
                } else {
                    RequirementOutcome.Fail(
                        "Legacy protocols offered: ${legacy.joinToString { it.displayName }}",
                        TlsSeverity.HIGH
                    )
                }
            },
            ComplianceRequirement(
                id = "MOZ_MOD_NO_NULL_CIPHER",
                title = "No NULL/anonymous/export/RC4/3DES cipher suites",
                spec = "Mozilla Modern §3.3"
            ) { r ->
                val bad = r.ciphersByProtocol.values.flatten().filter { c ->
                    CipherFlag.NULL_CIPHER in c.flags ||
                    CipherFlag.ANON_KX in c.flags ||
                    CipherFlag.EXPORT_GRADE in c.flags ||
                    CipherFlag.RC4 in c.flags ||
                    CipherFlag.TRIPLE_DES_64BIT_BLOCK in c.flags
                }
                if (bad.isEmpty()) RequirementOutcome.Pass()
                else RequirementOutcome.Fail(
                    "Weak cipher suites offered: ${bad.take(5).joinToString { it.name }}",
                    TlsSeverity.HIGH
                )
            },
            ComplianceRequirement(
                id = "MOZ_MOD_FS_REQUIRED",
                title = "All cipher suites must provide forward secrecy",
                spec = "Mozilla Modern §3.3"
            ) { r ->
                val noFs = r.ciphersByProtocol.values.flatten().filter {
                    CipherFlag.FORWARD_SECRECY !in it.flags
                }
                if (noFs.isEmpty()) RequirementOutcome.Pass()
                else RequirementOutcome.Fail(
                    "Non-FS cipher suites: ${noFs.take(5).joinToString { it.name }}",
                    TlsSeverity.MEDIUM
                )
            },
            ComplianceRequirement(
                id = "MOZ_MOD_CERT_SHA256",
                title = "Certificate signature must use SHA-256 or stronger",
                spec = "Mozilla Modern §3.4"
            ) { r ->
                val cert = r.leafCertificate
                    ?: return@ComplianceRequirement RequirementOutcome.NotTestable("No certificate captured")
                val hash = cert.signatureAlgorithm.hashAlgorithm.uppercase()
                if (hash.contains("SHA-1") || hash.contains("MD5")) {
                    RequirementOutcome.Fail(
                        "Weak hash algorithm: ${cert.signatureAlgorithm.hashAlgorithm}",
                        TlsSeverity.HIGH
                    )
                } else {
                    RequirementOutcome.Pass("Hash: ${cert.signatureAlgorithm.hashAlgorithm}")
                }
            },
            ComplianceRequirement(
                id = "MOZ_MOD_MUST_STAPLE",
                title = "Certificate should have OCSP must-staple (TLS Feature extension value 5)",
                spec = "Mozilla Modern §3.5 / RFC 7633"
            ) { r ->
                val cert = r.leafCertificate
                    ?: return@ComplianceRequirement RequirementOutcome.NotTestable("No certificate captured")
                // RFC 7633: must-staple = TLS Feature extension with value 5
                if (5 in cert.tlsFeature) {
                    RequirementOutcome.Pass("TLS Feature must-staple present")
                } else {
                    RequirementOutcome.Fail(
                        "Certificate does not declare OCSP must-staple (RFC 7633 value 5)",
                        TlsSeverity.LOW
                    )
                }
            }
        )
    )

    // ─── INTERMEDIATE ─────────────────────────────────────────────────────

    val INTERMEDIATE: CompliancePolicy = CompliancePolicy(
        id = "MOZILLA_INTERMEDIATE",
        displayName = "Mozilla SSL — Intermediate",
        version = "5.7 (2023-08)",
        reference = "https://wiki.mozilla.org/Security/Server_Side_TLS",
        requirements = listOf(
            ComplianceRequirement(
                id = "MOZ_INT_MIN_TLS12",
                title = "Minimum protocol version must be TLS 1.2",
                spec = "Mozilla Intermediate §3.1"
            ) { r ->
                val offered = offeredProtocols(r)
                val legacy = offered.filter {
                    it == TlsProtocol.SSL_2_0 || it == TlsProtocol.SSL_3_0 ||
                    it == TlsProtocol.TLS_1_0 || it == TlsProtocol.TLS_1_1
                }
                if (legacy.isEmpty()) RequirementOutcome.Pass()
                else RequirementOutcome.Fail(
                    "Legacy protocols offered: ${legacy.joinToString { it.displayName }}",
                    TlsSeverity.HIGH
                )
            },
            ComplianceRequirement(
                id = "MOZ_INT_NO_UNSAFE_CIPHERS",
                title = "No NULL/anonymous/export/RC4/3DES/CBC-only cipher suites",
                spec = "Mozilla Intermediate §3.3"
            ) { r ->
                val bad = r.ciphersByProtocol.values.flatten().filter { c ->
                    CipherFlag.NULL_CIPHER in c.flags ||
                    CipherFlag.ANON_KX in c.flags ||
                    CipherFlag.EXPORT_GRADE in c.flags ||
                    CipherFlag.RC4 in c.flags ||
                    CipherFlag.TRIPLE_DES_64BIT_BLOCK in c.flags
                }
                if (bad.isEmpty()) RequirementOutcome.Pass()
                else RequirementOutcome.Fail(
                    "Weak cipher suites offered: ${bad.take(5).joinToString { it.name }}",
                    TlsSeverity.HIGH
                )
            },
            ComplianceRequirement(
                id = "MOZ_INT_FS_PREFERRED",
                title = "Forward-secret cipher suites should be preferred",
                spec = "Mozilla Intermediate §3.3"
            ) { r ->
                val allCiphers = r.ciphersByProtocol.values.flatten()
                if (allCiphers.isEmpty()) return@ComplianceRequirement RequirementOutcome.NotTestable("No ciphers enumerated")
                val noFs = allCiphers.filter { CipherFlag.FORWARD_SECRECY !in it.flags }
                val fsRatio = (allCiphers.size - noFs.size).toDouble() / allCiphers.size
                if (fsRatio >= 0.5) RequirementOutcome.Pass("${(fsRatio * 100).toInt()}% FS ciphers")
                else RequirementOutcome.Fail(
                    "Less than 50% of cipher suites provide forward secrecy",
                    TlsSeverity.MEDIUM
                )
            },
            ComplianceRequirement(
                id = "MOZ_INT_CERT_SHA256",
                title = "Certificate signature must use SHA-256 or stronger",
                spec = "Mozilla Intermediate §3.4"
            ) { r ->
                val cert = r.leafCertificate
                    ?: return@ComplianceRequirement RequirementOutcome.NotTestable("No certificate captured")
                val hash = cert.signatureAlgorithm.hashAlgorithm.uppercase()
                if (hash.contains("SHA-1") || hash.contains("MD5")) {
                    RequirementOutcome.Fail(
                        "Weak hash algorithm: ${cert.signatureAlgorithm.hashAlgorithm}",
                        TlsSeverity.HIGH
                    )
                } else RequirementOutcome.Pass("Hash: ${cert.signatureAlgorithm.hashAlgorithm}")
            },
            ComplianceRequirement(
                id = "MOZ_INT_KEY_SIZE",
                title = "RSA keys ≥ 2048 bits, EC keys ≥ 256 bits",
                spec = "Mozilla Intermediate §3.4"
            ) { r ->
                val cert = r.leafCertificate
                    ?: return@ComplianceRequirement RequirementOutcome.NotTestable("No certificate captured")
                val pk = cert.publicKey
                val fail = when (pk.algorithm) {
                    "RSA", "DSA" -> pk.sizeBits < 2048
                    "EC"         -> pk.sizeBits < 256
                    else         -> false
                }
                if (fail) RequirementOutcome.Fail(
                    "${pk.algorithm} key too small: ${pk.sizeBits} bits",
                    TlsSeverity.HIGH
                )
                else RequirementOutcome.Pass("${pk.algorithm} ${pk.sizeBits}-bit key")
            },
            ComplianceRequirement(
                id = "MOZ_INT_OCSP_AIA",
                title = "Certificate must include OCSP URL in Authority Information Access",
                spec = "Mozilla Intermediate §3.5"
            ) { r ->
                val cert = r.leafCertificate
                    ?: return@ComplianceRequirement RequirementOutcome.NotTestable("No certificate captured")
                val ocspUrls = cert.authorityInfoAccess?.ocspUrls ?: emptyList()
                if (ocspUrls.isNotEmpty()) RequirementOutcome.Pass("OCSP URL: ${ocspUrls.first()}")
                else RequirementOutcome.Fail("No OCSP URL in AIA extension", TlsSeverity.MEDIUM)
            }
        )
    )

    // ─── OLD ──────────────────────────────────────────────────────────────

    val OLD: CompliancePolicy = CompliancePolicy(
        id = "MOZILLA_OLD",
        displayName = "Mozilla SSL — Old",
        version = "5.7 (2023-08)",
        reference = "https://wiki.mozilla.org/Security/Server_Side_TLS",
        requirements = listOf(
            ComplianceRequirement(
                id = "MOZ_OLD_MIN_TLS10",
                title = "Minimum protocol version: TLS 1.0 (SSLv2/v3 must NOT be offered)",
                spec = "Mozilla Old §3.1"
            ) { r ->
                val offered = offeredProtocols(r)
                val insecure = offered.filter {
                    it == TlsProtocol.SSL_2_0 || it == TlsProtocol.SSL_3_0
                }
                if (insecure.isEmpty()) RequirementOutcome.Pass()
                else RequirementOutcome.Fail(
                    "Critically deprecated protocols offered: ${insecure.joinToString { it.displayName }}",
                    TlsSeverity.CRITICAL
                )
            },
            ComplianceRequirement(
                id = "MOZ_OLD_NO_NULL_ANON",
                title = "No NULL or anonymous cipher suites",
                spec = "Mozilla Old §3.3"
            ) { r ->
                val bad = r.ciphersByProtocol.values.flatten().filter { c ->
                    CipherFlag.NULL_CIPHER in c.flags || CipherFlag.ANON_KX in c.flags
                }
                if (bad.isEmpty()) RequirementOutcome.Pass()
                else RequirementOutcome.Fail(
                    "NULL/anonymous ciphers: ${bad.take(5).joinToString { it.name }}",
                    TlsSeverity.CRITICAL
                )
            },
            ComplianceRequirement(
                id = "MOZ_OLD_NO_EXPORT",
                title = "No export-grade cipher suites",
                spec = "Mozilla Old §3.3"
            ) { r ->
                val bad = r.ciphersByProtocol.values.flatten().filter { c ->
                    CipherFlag.EXPORT_GRADE in c.flags
                }
                if (bad.isEmpty()) RequirementOutcome.Pass()
                else RequirementOutcome.Fail(
                    "Export-grade ciphers: ${bad.take(5).joinToString { it.name }}",
                    TlsSeverity.HIGH
                )
            },
            ComplianceRequirement(
                id = "MOZ_OLD_CERT_NOT_MD5",
                title = "Certificate signature must not use MD5",
                spec = "Mozilla Old §3.4"
            ) { r ->
                val cert = r.leafCertificate
                    ?: return@ComplianceRequirement RequirementOutcome.NotTestable("No certificate captured")
                if (cert.signatureAlgorithm.hashAlgorithm.uppercase().contains("MD5")) {
                    RequirementOutcome.Fail("MD5 signature hash algorithm in use", TlsSeverity.CRITICAL)
                } else {
                    RequirementOutcome.Pass("Hash: ${cert.signatureAlgorithm.hashAlgorithm}")
                }
            }
        )
    )
}
