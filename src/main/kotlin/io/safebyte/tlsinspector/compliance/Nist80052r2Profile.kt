package io.safebyte.tlsinspector.compliance

import io.safebyte.tlsinspector.CipherFlag
import io.safebyte.tlsinspector.ProtocolStatus
import io.safebyte.tlsinspector.TlsProtocol
import io.safebyte.tlsinspector.TlsSeverity

/**
 * NIST SP 800-52 Revision 2 TLS compliance profile.
 *
 * Key requirements (federal US government):
 *  - TLS 1.2 minimum for all servers; TLS 1.3 required for new server deployments
 *  - TLS 1.0 / 1.1 / SSL 3.0 / SSL 2.0 explicitly forbidden
 *  - Only NIST-approved cipher suites (AES-GCM, AES-CCM, ChaCha20-Poly1305)
 *  - ECDHE or DHE key exchange required (forward secrecy)
 *  - RSA keys ≥ 2048 bits, EC keys ≥ 256 bits (P-256, P-384 preferred)
 *  - Certificates must use SHA-256 or stronger
 *
 * Reference: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf
 */
object Nist80052r2Profile {

    private fun offeredProtocols(r: io.safebyte.tlsinspector.TlsScanResult) =
        r.protocolsOffered.filterValues { it == ProtocolStatus.OFFERED }.keys

    val POLICY: CompliancePolicy = CompliancePolicy(
        id = "NIST_800_52R2",
        displayName = "NIST SP 800-52r2",
        version = "r2 (2019-08)",
        reference = "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf",
        requirements = listOf(
            ComplianceRequirement(
                id = "NIST_NO_DEPRECATED_TLS",
                title = "No SSL 2.0, SSL 3.0, TLS 1.0, or TLS 1.1",
                spec = "NIST SP 800-52r2 §3.1"
            ) { r ->
                val offered = offeredProtocols(r)
                val deprecated = offered.filter {
                    it == TlsProtocol.SSL_2_0 || it == TlsProtocol.SSL_3_0 ||
                    it == TlsProtocol.TLS_1_0 || it == TlsProtocol.TLS_1_1
                }
                if (deprecated.isEmpty()) RequirementOutcome.Pass()
                else RequirementOutcome.Fail(
                    "Deprecated protocols offered: ${deprecated.joinToString { it.displayName }}",
                    TlsSeverity.HIGH
                )
            },
            ComplianceRequirement(
                id = "NIST_TLS12_OR_13_OFFERED",
                title = "TLS 1.2 or TLS 1.3 must be offered",
                spec = "NIST SP 800-52r2 §3.1"
            ) { r ->
                val offered = offeredProtocols(r)
                val modern = offered.filter {
                    it == TlsProtocol.TLS_1_2 || it == TlsProtocol.TLS_1_3
                }
                if (modern.isNotEmpty()) RequirementOutcome.Pass("Offered: ${modern.joinToString { it.displayName }}")
                else RequirementOutcome.Fail("Neither TLS 1.2 nor TLS 1.3 is offered", TlsSeverity.CRITICAL)
            },
            ComplianceRequirement(
                id = "NIST_NO_NULL_ANON",
                title = "No NULL or anonymous key exchange cipher suites",
                spec = "NIST SP 800-52r2 §3.3.1"
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
                id = "NIST_NO_EXPORT",
                title = "No export-grade cipher suites",
                spec = "NIST SP 800-52r2 §3.3.1"
            ) { r ->
                val bad = r.ciphersByProtocol.values.flatten().filter { CipherFlag.EXPORT_GRADE in it.flags }
                if (bad.isEmpty()) RequirementOutcome.Pass()
                else RequirementOutcome.Fail(
                    "Export-grade cipher suites: ${bad.take(5).joinToString { it.name }}",
                    TlsSeverity.HIGH
                )
            },
            ComplianceRequirement(
                id = "NIST_NO_RC4",
                title = "RC4 cipher suites are not approved",
                spec = "NIST SP 800-52r2 §3.3.1 / RFC 7465"
            ) { r ->
                val bad = r.ciphersByProtocol.values.flatten().filter { CipherFlag.RC4 in it.flags }
                if (bad.isEmpty()) RequirementOutcome.Pass()
                else RequirementOutcome.Fail(
                    "RC4 cipher suites: ${bad.take(5).joinToString { it.name }}",
                    TlsSeverity.HIGH
                )
            },
            ComplianceRequirement(
                id = "NIST_NO_3DES",
                title = "3DES cipher suites are not recommended (64-bit block size, birthday attack)",
                spec = "NIST SP 800-52r2 §3.3.1 / NIST SP 800-131Ar2"
            ) { r ->
                val bad = r.ciphersByProtocol.values.flatten().filter {
                    CipherFlag.TRIPLE_DES_64BIT_BLOCK in it.flags
                }
                if (bad.isEmpty()) RequirementOutcome.Pass()
                else RequirementOutcome.Fail(
                    "3DES cipher suites: ${bad.take(5).joinToString { it.name }}",
                    TlsSeverity.MEDIUM
                )
            },
            ComplianceRequirement(
                id = "NIST_FS_REQUIRED",
                title = "Ephemeral key exchange (ECDHE/DHE) required for perfect forward secrecy",
                spec = "NIST SP 800-52r2 §3.3.1"
            ) { r ->
                val allCiphers = r.ciphersByProtocol.values.flatten()
                if (allCiphers.isEmpty()) return@ComplianceRequirement RequirementOutcome.NotTestable("No ciphers enumerated")
                val noFs = allCiphers.filter { CipherFlag.FORWARD_SECRECY !in it.flags }
                if (noFs.isEmpty()) RequirementOutcome.Pass()
                else RequirementOutcome.Fail(
                    "Non-ephemeral cipher suites: ${noFs.take(5).joinToString { it.name }}",
                    TlsSeverity.MEDIUM
                )
            },
            ComplianceRequirement(
                id = "NIST_KEY_SIZE",
                title = "RSA keys ≥ 2048 bits, EC keys ≥ 256 bits (P-256, P-384 preferred)",
                spec = "NIST SP 800-52r2 §3.4 / NIST SP 800-131Ar2"
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
                id = "NIST_CERT_SHA256",
                title = "Certificate signature algorithm must be SHA-256 or stronger",
                spec = "NIST SP 800-52r2 §3.4 / NIST SP 800-131Ar2"
            ) { r ->
                val cert = r.leafCertificate
                    ?: return@ComplianceRequirement RequirementOutcome.NotTestable("No certificate captured")
                val hash = cert.signatureAlgorithm.hashAlgorithm.uppercase()
                if (hash.contains("SHA-1") || hash.contains("MD5")) {
                    RequirementOutcome.Fail("Weak signature hash: ${cert.signatureAlgorithm.hashAlgorithm}", TlsSeverity.HIGH)
                } else RequirementOutcome.Pass("Hash: ${cert.signatureAlgorithm.hashAlgorithm}")
            },
            ComplianceRequirement(
                id = "NIST_OCSP_AIA",
                title = "Certificate must provide OCSP revocation checking via AIA extension",
                spec = "NIST SP 800-52r2 §3.4"
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
