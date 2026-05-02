package io.safebyte.tlsinspector.certificate

import java.math.BigInteger
import java.time.Instant
import java.time.temporal.ChronoUnit

/**
 * Fully decomposed X.509 certificate. Every field that may appear in an issue or
 * the UI is extracted exactly once — probes consume this, never re-parse.
 */
data class ParsedCertificate(
    val derEncoded: ByteArray,
    val pemEncoded: String,

    // --- Standard fields ---
    val version: Int,                                    // 1, 2, or 3
    val serialNumber: BigInteger,
    val serialNumberHex: String,
    val signatureAlgorithm: SignatureAlgorithmInfo,
    val issuerDn: DistinguishedName,
    val subjectDn: DistinguishedName,
    val notBefore: Instant,
    val notAfter: Instant,
    val publicKey: PublicKeyInfo,

    // --- v3 extensions ---
    val subjectAlternativeNames: List<SanEntry>,
    val keyUsage: Set<KeyUsage>,
    val extendedKeyUsage: List<String>,                  // OIDs
    val extendedKeyUsageNames: List<String>,             // human-readable
    val basicConstraints: BasicConstraints?,
    val authorityInfoAccess: AuthorityInfoAccess?,
    val crlDistributionPoints: List<String>,
    val certificatePolicies: List<String>,               // OIDs
    val subjectKeyIdentifier: String?,                   // hex
    val authorityKeyIdentifier: String?,                 // hex
    val nameConstraints: NameConstraintsInfo?,
    val precertificateScts: List<SctInfo>,               // RFC 6962 — may be empty
    val tlsFeature: List<Int>,                           // RFC 7633 — typically [5] = must-staple
    val unknownCriticalExtensions: List<String>,         // OIDs of unrecognized critical extensions

    // --- Derived / computed ---
    val sha1Fingerprint: String,                         // hex, lowercase, no separators
    val sha256Fingerprint: String,
    val sha512Fingerprint: String,
    val spkiSha256Hash: String,                          // for HPKP / pinning / reuse detection
    val isSelfSigned: Boolean,                           // subject == issuer && self-signature valid
    val validityDays: Long,                              // notAfter - notBefore in days
    val daysToExpiry: Long,                              // can be negative if expired
    val isExpired: Boolean,
    val isNotYetValid: Boolean
) {
    companion object {
        fun computeDaysToExpiry(notAfter: Instant, now: Instant = Instant.now()): Long =
            ChronoUnit.DAYS.between(now, notAfter)
    }
}

data class SignatureAlgorithmInfo(
    val oid: String,
    val name: String,                  // e.g. "sha256WithRSAEncryption", "ecdsa-with-SHA384"
    val hashAlgorithm: String,         // SHA-1, SHA-256, SHA-384, SHA-512, MD5
    val publicKeyAlgorithm: String     // RSA, ECDSA, Ed25519, Ed448, DSA
)

data class DistinguishedName(
    val raw: String,                   // RFC 2253 string, e.g. "CN=example.com,O=Example Inc,C=US"
    val commonName: String?,
    val organization: String?,
    val organizationalUnit: String?,
    val country: String?,
    val state: String?,
    val locality: String?,
    val emailAddress: String?,
    val attributes: Map<String, List<String>>   // OID -> values, for attributes not in fast-path above
)

data class PublicKeyInfo(
    val algorithm: String,             // "RSA", "EC", "DSA", "Ed25519", "Ed448", "X25519", "X448"
    val sizeBits: Int,                 // RSA modulus size, EC field size, etc.
    val curveName: String? = null,     // for EC: "P-256", "P-384", "secp192r1", "brainpoolP256r1"
    val curveOid: String? = null,      // for EC
    val rsaModulusHex: String? = null, // RSA: full modulus N for ROBOT probe later
    val rsaExponent: BigInteger? = null
)

data class SanEntry(
    val type: SanType,
    val value: String                  // for IPv4: "192.0.2.1", for DNS: "example.com" or "*.example.com"
)

enum class SanType { DNS, IP_ADDRESS, EMAIL, URI, OTHER }

enum class KeyUsage {
    DIGITAL_SIGNATURE, NON_REPUDIATION, KEY_ENCIPHERMENT, DATA_ENCIPHERMENT,
    KEY_AGREEMENT, KEY_CERT_SIGN, CRL_SIGN, ENCIPHER_ONLY, DECIPHER_ONLY
}

data class BasicConstraints(val isCa: Boolean, val pathLenConstraint: Int?)

data class AuthorityInfoAccess(
    val ocspUrls: List<String>,
    val caIssuersUrls: List<String>
)

data class NameConstraintsInfo(
    val permittedSubtrees: List<String>,
    val excludedSubtrees: List<String>
)

data class SctInfo(
    val version: Int,
    val logIdHex: String,
    val timestamp: Instant,
    val signatureAlgorithm: String
)
