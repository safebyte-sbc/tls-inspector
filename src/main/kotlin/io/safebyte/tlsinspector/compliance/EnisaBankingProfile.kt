package io.safebyte.tlsinspector.compliance

import io.safebyte.tlsinspector.CipherFlag
import io.safebyte.tlsinspector.ProtocolStatus
import io.safebyte.tlsinspector.TlsProtocol
import io.safebyte.tlsinspector.TlsSeverity

/**
 * ENISA + ETSI TS 119 312 banking/financial TLS compliance profile.
 * Aligns with EBA ICT Risk Guidelines for EU financial institutions.
 *
 * Key requirements:
 *  - TLS 1.2 minimum; TLS 1.3 strongly recommended
 *  - No export, NULL, RC4, 3DES, anonymous, or CBC-only cipher suites
 *  - All cipher suites must provide forward secrecy (ECDHE/DHE)
 *  - AEAD cipher modes required (AES-GCM, ChaCha20-Poly1305)
 *  - RSA keys ≥ 2048 bits, EC keys ≥ 256 bits
 *  - SHA-256 or stronger certificate signatures
 *  - OCSP revocation URL in AIA (real-time revocation checking)
 *  - OCSP must-staple recommended
 *  - CT logging (NotTestable — SCT extraction not implemented in this milestone)
 *
 * Reference: ETSI TS 119 312 v1.4.1, ENISA TLS Guidelines 2021,
 *            EBA GL/2019/04 ICT Risk Management §5.3.2
 */
object EnisaBankingProfile {

    private fun offeredProtocols(r: io.safebyte.tlsinspector.TlsScanResult) =
        r.protocolsOffered.filterValues { it == ProtocolStatus.OFFERED }.keys

    val POLICY: CompliancePolicy = CompliancePolicy(
        id = "ENISA_BANKING",
        displayName = "ENISA + ETSI TS 119 312 (EU banking baseline)",
        version = "ETSI TS 119 312 v1.4.1 / ENISA TLS Guidelines 2021",
        reference = "https://www.etsi.org/deliver/etsi_ts/119300_119399/119312/01.04.01_60/ts_119312v010401p.pdf",
        requirements = listOf(
            ComplianceRequirement(
                id = "ENISA_NO_DEPRECATED",
                title = "No SSL 2.0, SSL 3.0, TLS 1.0, or TLS 1.1 — deprecated under EBA ICT Risk Guidelines",
                spec = "ETSI TS 119 312 §6.3 / EBA GL/2019/04 §5.3.2"
            ) { r ->
                val offered = offeredProtocols(r)
                val deprecated = offered.filter {
                    it == TlsProtocol.SSL_2_0 || it == TlsProtocol.SSL_3_0 ||
                    it == TlsProtocol.TLS_1_0 || it == TlsProtocol.TLS_1_1
                }
                if (deprecated.isEmpty()) RequirementOutcome.Pass()
                else RequirementOutcome.Fail(
                    "Deprecated protocols offered: ${deprecated.joinToString { it.displayName }}. " +
                    "EBA ICT Risk Guidelines require migration off TLS 1.0/1.1 for financial services.",
                    TlsSeverity.HIGH
                )
            },
            ComplianceRequirement(
                id = "ENISA_TLS12_13_REQUIRED",
                title = "TLS 1.2 or TLS 1.3 must be supported",
                spec = "ETSI TS 119 312 §6.3"
            ) { r ->
                val offered = offeredProtocols(r)
                val modern = offered.filter { it == TlsProtocol.TLS_1_2 || it == TlsProtocol.TLS_1_3 }
                if (modern.isNotEmpty()) RequirementOutcome.Pass("Offered: ${modern.joinToString { it.displayName }}")
                else RequirementOutcome.Fail("Neither TLS 1.2 nor TLS 1.3 is offered", TlsSeverity.CRITICAL)
            },
            ComplianceRequirement(
                id = "ENISA_NO_NULL_ANON",
                title = "No NULL or anonymous cipher suites",
                spec = "ETSI TS 119 312 §6.4"
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
                id = "ENISA_NO_EXPORT",
                title = "No export-grade cipher suites",
                spec = "ETSI TS 119 312 §6.4"
            ) { r ->
                val bad = r.ciphersByProtocol.values.flatten().filter { CipherFlag.EXPORT_GRADE in it.flags }
                if (bad.isEmpty()) RequirementOutcome.Pass()
                else RequirementOutcome.Fail(
                    "Export-grade cipher suites: ${bad.take(5).joinToString { it.name }}",
                    TlsSeverity.HIGH
                )
            },
            ComplianceRequirement(
                id = "ENISA_NO_RC4",
                title = "No RC4 cipher suites (prohibited by RFC 7465)",
                spec = "ETSI TS 119 312 §6.4 / RFC 7465"
            ) { r ->
                val bad = r.ciphersByProtocol.values.flatten().filter { CipherFlag.RC4 in it.flags }
                if (bad.isEmpty()) RequirementOutcome.Pass()
                else RequirementOutcome.Fail(
                    "RC4 cipher suites: ${bad.take(5).joinToString { it.name }}",
                    TlsSeverity.HIGH
                )
            },
            ComplianceRequirement(
                id = "ENISA_NO_3DES",
                title = "No 3DES cipher suites (SWEET32 birthday attack, CVE-2016-2183)",
                spec = "ETSI TS 119 312 §6.4 / ENISA TLS Guidelines §3.2"
            ) { r ->
                val bad = r.ciphersByProtocol.values.flatten().filter {
                    CipherFlag.TRIPLE_DES_64BIT_BLOCK in it.flags
                }
                if (bad.isEmpty()) RequirementOutcome.Pass()
                else RequirementOutcome.Fail(
                    "3DES cipher suites offered: ${bad.take(5).joinToString { it.name }}",
                    TlsSeverity.MEDIUM
                )
            },
            ComplianceRequirement(
                id = "ENISA_NO_CBC",
                title = "No CBC cipher suites without AEAD (Lucky13, BEAST risk)",
                spec = "ENISA TLS Guidelines §3.2 / ETSI TS 119 312 §6.4"
            ) { r ->
                val bad = r.ciphersByProtocol.values.flatten().filter {
                    CipherFlag.CBC_NO_AEAD in it.flags
                }
                if (bad.isEmpty()) RequirementOutcome.Pass()
                else RequirementOutcome.Fail(
                    "CBC (non-AEAD) cipher suites: ${bad.take(5).joinToString { it.name }}",
                    TlsSeverity.MEDIUM
                )
            },
            ComplianceRequirement(
                id = "ENISA_FS_REQUIRED",
                title = "All cipher suites must provide perfect forward secrecy (ECDHE/DHE)",
                spec = "ETSI TS 119 312 §6.4 / ENISA TLS Guidelines §3.3"
            ) { r ->
                val allCiphers = r.ciphersByProtocol.values.flatten()
                if (allCiphers.isEmpty()) return@ComplianceRequirement RequirementOutcome.NotTestable("No ciphers enumerated")
                val noFs = allCiphers.filter { CipherFlag.FORWARD_SECRECY !in it.flags }
                if (noFs.isEmpty()) RequirementOutcome.Pass()
                else RequirementOutcome.Fail(
                    "Non-forward-secret ciphers: ${noFs.take(5).joinToString { it.name }}",
                    TlsSeverity.HIGH
                )
            },
            ComplianceRequirement(
                id = "ENISA_AEAD_REQUIRED",
                title = "AEAD cipher modes required (AES-GCM / ChaCha20-Poly1305)",
                spec = "ETSI TS 119 312 §6.4 / ENISA TLS Guidelines §3.2"
            ) { r ->
                val allCiphers = r.ciphersByProtocol.values.flatten()
                if (allCiphers.isEmpty()) return@ComplianceRequirement RequirementOutcome.NotTestable("No ciphers enumerated")
                val aeadCount = allCiphers.count { CipherFlag.AEAD in it.flags }
                if (aeadCount > 0) RequirementOutcome.Pass("$aeadCount AEAD cipher suites offered")
                else RequirementOutcome.Fail("No AEAD cipher suites offered (AES-GCM or ChaCha20-Poly1305 required)", TlsSeverity.HIGH)
            },
            ComplianceRequirement(
                id = "ENISA_KEY_SIZE",
                title = "RSA keys ≥ 2048 bits, EC keys ≥ 256 bits",
                spec = "ETSI TS 119 312 §6.5 / ENISA Crypto Guidelines 2021"
            ) { r ->
                val cert = r.leafCertificate
                    ?: return@ComplianceRequirement RequirementOutcome.NotTestable("No certificate captured")
                val pk = cert.publicKey
                val fail = when (pk.algorithm) {
                    "RSA", "DSA" -> pk.sizeBits < 2048
                    "EC"         -> pk.sizeBits < 256
                    else         -> false
                }
                if (fail) RequirementOutcome.Fail("${pk.algorithm} key too small: ${pk.sizeBits} bits", TlsSeverity.HIGH)
                else RequirementOutcome.Pass("${pk.algorithm} ${pk.sizeBits}-bit key")
            },
            ComplianceRequirement(
                id = "ENISA_CERT_SHA256",
                title = "Certificate signature must use SHA-256 or stronger",
                spec = "ETSI TS 119 312 §6.5"
            ) { r ->
                val cert = r.leafCertificate
                    ?: return@ComplianceRequirement RequirementOutcome.NotTestable("No certificate captured")
                val hash = cert.signatureAlgorithm.hashAlgorithm.uppercase()
                if (hash.contains("SHA-1") || hash.contains("MD5")) {
                    RequirementOutcome.Fail("Weak hash: ${cert.signatureAlgorithm.hashAlgorithm}", TlsSeverity.HIGH)
                } else RequirementOutcome.Pass("Hash: ${cert.signatureAlgorithm.hashAlgorithm}")
            },
            ComplianceRequirement(
                id = "ENISA_OCSP_AIA",
                title = "Certificate must include OCSP URL in Authority Information Access",
                spec = "ETSI TS 119 312 §6.5 / EBA GL/2019/04 §5.3.2"
            ) { r ->
                val cert = r.leafCertificate
                    ?: return@ComplianceRequirement RequirementOutcome.NotTestable("No certificate captured")
                val ocspUrls = cert.authorityInfoAccess?.ocspUrls ?: emptyList()
                if (ocspUrls.isNotEmpty()) RequirementOutcome.Pass("OCSP URL: ${ocspUrls.first()}")
                else RequirementOutcome.Fail("No OCSP URL in AIA extension (revocation checking mandatory for financial services)", TlsSeverity.HIGH)
            },
            ComplianceRequirement(
                id = "ENISA_CT_LOGGED",
                title = "Certificate should be logged in Certificate Transparency (RFC 6962)",
                spec = "CA/Browser Forum Baseline Requirements §3.3.1 / RFC 6962"
            ) { _ ->
                // GAP: SignedCertificateTimestamps (SCTs) are present in ParsedCertificate as
                // precertificateScts (RFC 6962 embedded SCTs). Full SCT count validation deferred
                // to MS E when TLS extension SCTs (from OcspStaplingProbe handshake) are also extracted.
                // For now, return NotTestable to avoid false positives.
                RequirementOutcome.NotTestable(
                    "SCT extraction not yet fully implemented — CT log requirement deferred to MS E. " +
                    "Embedded precertificate SCTs exist in ParsedCertificate.precertificateScts but " +
                    "TLS extension and OCSP staple SCTs not yet aggregated."
                )
            }
        )
    )
}
