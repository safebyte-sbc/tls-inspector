package io.safebyte.tlsinspector.compliance

import io.safebyte.tlsinspector.CipherFlag
import io.safebyte.tlsinspector.ProtocolStatus
import io.safebyte.tlsinspector.TlsProtocol
import io.safebyte.tlsinspector.TlsSeverity

/**
 * PCI DSS 4.0 §4.2.1 TLS compliance profile.
 *
 * Key requirements:
 *  - TLS 1.2 minimum (1.0 / 1.1 / SSL 3.0 / SSL 2.0 explicitly forbidden as of 30 Jun 2018)
 *  - No early TLS (PCI DSS 3.2.1+ definition: SSL and early TLS)
 *  - No export, NULL, RC4, or anonymous cipher suites
 *  - No 3DES in new deployments (PCI DSS 4.0 deprecates short block-size ciphers)
 *  - Forward-secret cipher suites required for new deployments
 *  - RSA keys ≥ 2048-bit, EC keys ≥ 256-bit
 *  - OCSP revocation URL in AIA
 *
 * Reference: https://www.pcisecuritystandards.org/document_library/?category=pcidss
 */
object PciDss40Profile {

    private fun offeredProtocols(r: io.safebyte.tlsinspector.TlsScanResult) =
        r.protocolsOffered.filterValues { it == ProtocolStatus.OFFERED }.keys

    val POLICY: CompliancePolicy = CompliancePolicy(
        id = "PCI_DSS_4",
        displayName = "PCI DSS 4.0 §4.2.1",
        version = "4.0 (2022-03)",
        reference = "https://www.pcisecuritystandards.org/document_library/",
        requirements = listOf(
            ComplianceRequirement(
                id = "PCI_NO_EARLY_TLS",
                title = "No early TLS (SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1) must be offered",
                spec = "PCI DSS 4.0 §4.2.1 / Bulletin: Migrating from SSL and Early TLS"
            ) { r ->
                val offered = offeredProtocols(r)
                val early = offered.filter {
                    it == TlsProtocol.SSL_2_0 || it == TlsProtocol.SSL_3_0 ||
                    it == TlsProtocol.TLS_1_0 || it == TlsProtocol.TLS_1_1
                }
                if (early.isEmpty()) RequirementOutcome.Pass()
                else RequirementOutcome.Fail(
                    "Early TLS / SSL protocols offered: ${early.joinToString { it.displayName }}. " +
                    "PCI DSS requires migration off all early TLS (deadline passed: 30 Jun 2018).",
                    TlsSeverity.CRITICAL
                )
            },
            ComplianceRequirement(
                id = "PCI_NO_NULL_ANON",
                title = "No NULL or anonymous cipher suites",
                spec = "PCI DSS 4.0 §4.2.1"
            ) { r ->
                val bad = r.ciphersByProtocol.values.flatten().filter { c ->
                    CipherFlag.NULL_CIPHER in c.flags || CipherFlag.ANON_KX in c.flags
                }
                if (bad.isEmpty()) RequirementOutcome.Pass()
                else RequirementOutcome.Fail(
                    "NULL/anonymous cipher suites offered: ${bad.take(5).joinToString { it.name }}",
                    TlsSeverity.CRITICAL
                )
            },
            ComplianceRequirement(
                id = "PCI_NO_EXPORT",
                title = "No export-grade cipher suites",
                spec = "PCI DSS 4.0 §4.2.1"
            ) { r ->
                val bad = r.ciphersByProtocol.values.flatten().filter { CipherFlag.EXPORT_GRADE in it.flags }
                if (bad.isEmpty()) RequirementOutcome.Pass()
                else RequirementOutcome.Fail(
                    "Export-grade cipher suites offered: ${bad.take(5).joinToString { it.name }}",
                    TlsSeverity.HIGH
                )
            },
            ComplianceRequirement(
                id = "PCI_NO_RC4",
                title = "No RC4 cipher suites",
                spec = "PCI DSS 4.0 §4.2.1 / RFC 7465"
            ) { r ->
                val bad = r.ciphersByProtocol.values.flatten().filter { CipherFlag.RC4 in it.flags }
                if (bad.isEmpty()) RequirementOutcome.Pass()
                else RequirementOutcome.Fail(
                    "RC4 cipher suites offered: ${bad.take(5).joinToString { it.name }}",
                    TlsSeverity.HIGH
                )
            },
            ComplianceRequirement(
                id = "PCI_NO_3DES",
                title = "No 3DES (SWEET32) cipher suites in new deployments",
                spec = "PCI DSS 4.0 §4.2.1 / CVE-2016-2183"
            ) { r ->
                val bad = r.ciphersByProtocol.values.flatten().filter {
                    CipherFlag.TRIPLE_DES_64BIT_BLOCK in it.flags
                }
                if (bad.isEmpty()) RequirementOutcome.Pass()
                else RequirementOutcome.Fail(
                    "3DES cipher suites offered (birthday attack at ~785 GB): ${bad.take(5).joinToString { it.name }}",
                    TlsSeverity.MEDIUM
                )
            },
            ComplianceRequirement(
                id = "PCI_FS_REQUIRED",
                title = "Forward-secret cipher suites required",
                spec = "PCI DSS 4.0 §4.2.1"
            ) { r ->
                val allCiphers = r.ciphersByProtocol.values.flatten()
                if (allCiphers.isEmpty()) return@ComplianceRequirement RequirementOutcome.NotTestable("No ciphers enumerated")
                val noFs = allCiphers.filter { CipherFlag.FORWARD_SECRECY !in it.flags }
                if (noFs.isEmpty()) RequirementOutcome.Pass()
                else RequirementOutcome.Fail(
                    "Non-forward-secret cipher suites offered: ${noFs.take(5).joinToString { it.name }}",
                    TlsSeverity.MEDIUM
                )
            },
            ComplianceRequirement(
                id = "PCI_KEY_SIZE",
                title = "RSA keys ≥ 2048 bits, EC keys ≥ 256 bits",
                spec = "PCI DSS 4.0 §4.2.1"
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
                id = "PCI_CERT_SHA256",
                title = "Certificate signature must use SHA-256 or stronger",
                spec = "PCI DSS 4.0 §4.2.1"
            ) { r ->
                val cert = r.leafCertificate
                    ?: return@ComplianceRequirement RequirementOutcome.NotTestable("No certificate captured")
                val hash = cert.signatureAlgorithm.hashAlgorithm.uppercase()
                if (hash.contains("SHA-1") || hash.contains("MD5")) {
                    RequirementOutcome.Fail("Weak signature hash: ${cert.signatureAlgorithm.hashAlgorithm}", TlsSeverity.HIGH)
                } else RequirementOutcome.Pass("Hash: ${cert.signatureAlgorithm.hashAlgorithm}")
            },
            ComplianceRequirement(
                id = "PCI_OCSP_AIA",
                title = "Certificate OCSP URL present in Authority Information Access",
                spec = "PCI DSS 4.0 §4.2.1"
            ) { r ->
                val cert = r.leafCertificate
                    ?: return@ComplianceRequirement RequirementOutcome.NotTestable("No certificate captured")
                val ocspUrls = cert.authorityInfoAccess?.ocspUrls ?: emptyList()
                if (ocspUrls.isNotEmpty()) RequirementOutcome.Pass("OCSP URL: ${ocspUrls.first()}")
                else RequirementOutcome.Fail("No OCSP URL in AIA extension", TlsSeverity.MEDIUM)
            }
        )
    )
}
