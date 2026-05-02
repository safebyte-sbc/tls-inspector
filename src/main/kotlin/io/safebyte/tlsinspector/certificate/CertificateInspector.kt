package io.safebyte.tlsinspector.certificate

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import java.io.StringWriter
import java.math.BigInteger
import java.security.MessageDigest
import java.security.PublicKey
import java.security.Security
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.time.Instant

/**
 * Parses a DER-encoded certificate into a fully decomposed ParsedCertificate.
 * Stateless, thread-safe, no I/O.
 */
object CertificateInspector {

    init { Security.addProvider(BouncyCastleProvider()) }

    private val converter = JcaX509CertificateConverter().setProvider("BC")

    fun parse(der: ByteArray, now: Instant = Instant.now()): ParsedCertificate {
        val holder = X509CertificateHolder(der)
        val x509: X509Certificate = converter.getCertificate(holder)

        val notBefore = x509.notBefore.toInstant()
        val notAfter = x509.notAfter.toInstant()

        val san = SanExtractor.extract(holder)
        val pubKey = PublicKeyExtractor.extract(x509.publicKey)
        val sigAlgo = SignatureAlgorithmExtractor.extract(x509)
        val keyUsage = KeyUsageExtractor.extract(x509)
        val ekuOids = ExtendedKeyUsageExtractor.extractOids(x509)
        val ekuNames = ekuOids.map { ExtendedKeyUsageExtractor.nameFor(it) }
        val basicConstraints = BasicConstraintsExtractor.extract(x509)
        val aia = AiaExtractor.extract(holder)
        val crls = CrlDpExtractor.extract(holder)
        val policies = CertificatePoliciesExtractor.extract(holder)
        val ski = subjectKeyIdHex(holder)
        val aki = authorityKeyIdHex(holder)
        val nameConstraints = NameConstraintsExtractor.extract(holder)
        val scts = SctExtractor.extract(holder)
        val tlsFeature = TlsFeatureExtractor.extract(holder)
        val unknownCriticalExtensions = unknownCriticalExtensionOids(holder)

        val pem = derToPem(der, "CERTIFICATE")
        val sha1 = hex(MessageDigest.getInstance("SHA-1").digest(der))
        val sha256 = hex(MessageDigest.getInstance("SHA-256").digest(der))
        val sha512 = hex(MessageDigest.getInstance("SHA-512").digest(der))
        val spki = hex(MessageDigest.getInstance("SHA-256").digest(x509.publicKey.encoded))

        val isSelfSigned = isSelfSigned(x509)

        val validityDays = java.time.temporal.ChronoUnit.DAYS.between(notBefore, notAfter)
        val daysToExpiry = ParsedCertificate.computeDaysToExpiry(notAfter, now)

        return ParsedCertificate(
            derEncoded = der,
            pemEncoded = pem,
            version = x509.version,
            serialNumber = x509.serialNumber,
            serialNumberHex = x509.serialNumber.toString(16),
            signatureAlgorithm = sigAlgo,
            issuerDn = parseDn(holder.issuer),
            subjectDn = parseDn(holder.subject),
            notBefore = notBefore,
            notAfter = notAfter,
            publicKey = pubKey,
            subjectAlternativeNames = san,
            keyUsage = keyUsage,
            extendedKeyUsage = ekuOids,
            extendedKeyUsageNames = ekuNames,
            basicConstraints = basicConstraints,
            authorityInfoAccess = aia,
            crlDistributionPoints = crls,
            certificatePolicies = policies,
            subjectKeyIdentifier = ski,
            authorityKeyIdentifier = aki,
            nameConstraints = nameConstraints,
            precertificateScts = scts,
            tlsFeature = tlsFeature,
            unknownCriticalExtensions = unknownCriticalExtensions,
            sha1Fingerprint = sha1,
            sha256Fingerprint = sha256,
            sha512Fingerprint = sha512,
            spkiSha256Hash = spki,
            isSelfSigned = isSelfSigned,
            validityDays = validityDays,
            daysToExpiry = daysToExpiry,
            isExpired = now.isAfter(notAfter),
            isNotYetValid = now.isBefore(notBefore)
        )
    }

    fun parseChain(chainDer: List<ByteArray>): List<ParsedCertificate> = chainDer.map { parse(it) }

    private fun parseDn(name: X500Name): DistinguishedName {
        fun firstAttr(oid: ASN1ObjectIdentifier): String? =
            name.getRDNs(oid).firstOrNull()?.first?.value?.toString()

        val attrs = mutableMapOf<String, MutableList<String>>()
        for (rdn in name.getRDNs()) {
            for (typeAndValue in rdn.typesAndValues) {
                val oid = typeAndValue.type.id
                attrs.getOrPut(oid) { mutableListOf() }.add(typeAndValue.value.toString())
            }
        }

        return DistinguishedName(
            raw = name.toString(),
            commonName = firstAttr(BCStyle.CN),
            organization = firstAttr(BCStyle.O),
            organizationalUnit = firstAttr(BCStyle.OU),
            country = firstAttr(BCStyle.C),
            state = firstAttr(BCStyle.ST),
            locality = firstAttr(BCStyle.L),
            emailAddress = firstAttr(BCStyle.E),
            attributes = attrs.mapValues { it.value.toList() }
        )
    }

    private fun isSelfSigned(cert: X509Certificate): Boolean {
        if (cert.subjectX500Principal != cert.issuerX500Principal) return false
        return try {
            cert.verify(cert.publicKey)
            true
        } catch (_: Exception) {
            false
        }
    }

    private fun subjectKeyIdHex(holder: X509CertificateHolder): String? {
        val ext = holder.getExtension(Extension.subjectKeyIdentifier) ?: return null
        return hex(org.bouncycastle.asn1.x509.SubjectKeyIdentifier.getInstance(ext.parsedValue).keyIdentifier)
    }

    private fun authorityKeyIdHex(holder: X509CertificateHolder): String? {
        val ext = holder.getExtension(Extension.authorityKeyIdentifier) ?: return null
        val aki = org.bouncycastle.asn1.x509.AuthorityKeyIdentifier.getInstance(ext.parsedValue)
        return aki.keyIdentifier?.let { hex(it) }
    }

    private fun unknownCriticalExtensionOids(holder: X509CertificateHolder): List<String> {
        val known = setOf(
            Extension.basicConstraints.id,
            Extension.keyUsage.id,
            Extension.subjectAlternativeName.id,
            Extension.extendedKeyUsage.id,
            Extension.subjectKeyIdentifier.id,
            Extension.authorityKeyIdentifier.id,
            Extension.authorityInfoAccess.id,
            Extension.cRLDistributionPoints.id,
            Extension.certificatePolicies.id,
            Extension.policyConstraints.id,
            Extension.policyMappings.id,
            Extension.nameConstraints.id,
            Extension.inhibitAnyPolicy.id,
            "1.3.6.1.4.1.11129.2.4.2",   // CT precertificate SCTs
            "1.3.6.1.4.1.11129.2.4.3",   // CT precertificate poison
            "1.3.6.1.5.5.7.1.24"          // TLS feature (RFC 7633)
        )
        return holder.criticalExtensionOIDs
            .map { it.toString() }
            .filter { it !in known }
    }

    private fun derToPem(der: ByteArray, type: String): String {
        val sw = StringWriter()
        JcaPEMWriter(sw).use { it.writeObject(org.bouncycastle.util.io.pem.PemObject(type, der)) }
        return sw.toString()
    }

    fun hex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it) }
}

// ---- Helper extractors (one per X.509 extension family) -----------------------

internal object SanExtractor {
    fun extract(holder: X509CertificateHolder): List<SanEntry> {
        val ext = holder.getExtension(Extension.subjectAlternativeName) ?: return emptyList()
        val names = org.bouncycastle.asn1.x509.GeneralNames.getInstance(ext.parsedValue)
        return names.names.mapNotNull { gn ->
            when (gn.tagNo) {
                org.bouncycastle.asn1.x509.GeneralName.dNSName ->
                    SanEntry(SanType.DNS, gn.name.toString())
                org.bouncycastle.asn1.x509.GeneralName.iPAddress ->
                    SanEntry(SanType.IP_ADDRESS, parseIpAddress(gn))
                org.bouncycastle.asn1.x509.GeneralName.rfc822Name ->
                    SanEntry(SanType.EMAIL, gn.name.toString())
                org.bouncycastle.asn1.x509.GeneralName.uniformResourceIdentifier ->
                    SanEntry(SanType.URI, gn.name.toString())
                else -> SanEntry(SanType.OTHER, gn.name.toString())
            }
        }
    }

    private fun parseIpAddress(gn: org.bouncycastle.asn1.x509.GeneralName): String {
        val octets = (gn.name as org.bouncycastle.asn1.ASN1OctetString).octets
        return when (octets.size) {
            4 -> octets.joinToString(".") { (it.toInt() and 0xff).toString() }
            16 -> {
                val sb = StringBuilder()
                for (i in 0 until 16 step 2) {
                    if (i > 0) sb.append(':')
                    sb.append("%02x%02x".format(octets[i], octets[i + 1]))
                }
                sb.toString()
            }
            else -> "<unparseable IP>"
        }
    }
}

internal object PublicKeyExtractor {
    fun extract(pk: PublicKey): PublicKeyInfo = when (pk) {
        is RSAPublicKey -> PublicKeyInfo(
            algorithm = "RSA",
            sizeBits = pk.modulus.bitLength(),
            rsaModulusHex = pk.modulus.toString(16),
            rsaExponent = pk.publicExponent
        )
        is ECPublicKey -> {
            val curveName = pk.params?.let { ecCurveName(pk) }
            PublicKeyInfo(
                algorithm = "EC",
                sizeBits = pk.params?.curve?.field?.fieldSize ?: 0,
                curveName = curveName,
                curveOid = ecCurveOid(pk)
            )
        }
        else -> {
            val algoName = pk.algorithm ?: "UNKNOWN"
            PublicKeyInfo(algorithm = algoName, sizeBits = pk.encoded.size * 8)
        }
    }

    private fun ecCurveName(pk: ECPublicKey): String? {
        val params = pk.params ?: return null
        val fieldSize = params.curve.field.fieldSize
        return when (fieldSize) {
            192 -> "secp192r1"
            224 -> "secp224r1"
            256 -> "P-256 (prime256v1 / secp256r1)"
            384 -> "P-384 (secp384r1)"
            521 -> "P-521 (secp521r1)"
            else -> "EC-${fieldSize}bit"
        }
    }

    private fun ecCurveOid(pk: ECPublicKey): String? {
        return try {
            val spki = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(pk.encoded)
            (spki.algorithm.parameters as? ASN1ObjectIdentifier)?.id
        } catch (_: Exception) { null }
    }
}

internal object SignatureAlgorithmExtractor {
    fun extract(cert: X509Certificate): SignatureAlgorithmInfo {
        val oid = cert.sigAlgOID
        val name = cert.sigAlgName ?: oid
        val (hashAlgo, pkAlgo) = parseSigAlgo(oid, name)
        return SignatureAlgorithmInfo(oid, name, hashAlgo, pkAlgo)
    }

    private fun parseSigAlgo(oid: String, name: String): Pair<String, String> {
        val nameLower = name.lowercase()
        val hash = when {
            "md5" in nameLower -> "MD5"
            "sha1" in nameLower || "sha-1" in nameLower -> "SHA-1"
            "sha224" in nameLower -> "SHA-224"
            "sha256" in nameLower -> "SHA-256"
            "sha384" in nameLower -> "SHA-384"
            "sha512" in nameLower -> "SHA-512"
            "ed25519" in nameLower -> "Ed25519"
            "ed448" in nameLower -> "Ed448"
            else -> "Unknown"
        }
        val pk = when {
            "rsa" in nameLower -> "RSA"
            "ecdsa" in nameLower -> "ECDSA"
            "dsa" in nameLower -> "DSA"
            "ed25519" in nameLower -> "Ed25519"
            "ed448" in nameLower -> "Ed448"
            else -> "Unknown"
        }
        return hash to pk
    }
}

internal object KeyUsageExtractor {
    fun extract(cert: X509Certificate): Set<KeyUsage> {
        val bits = cert.keyUsage ?: return emptySet()
        val out = mutableSetOf<KeyUsage>()
        if (bits.size > 0 && bits[0]) out.add(KeyUsage.DIGITAL_SIGNATURE)
        if (bits.size > 1 && bits[1]) out.add(KeyUsage.NON_REPUDIATION)
        if (bits.size > 2 && bits[2]) out.add(KeyUsage.KEY_ENCIPHERMENT)
        if (bits.size > 3 && bits[3]) out.add(KeyUsage.DATA_ENCIPHERMENT)
        if (bits.size > 4 && bits[4]) out.add(KeyUsage.KEY_AGREEMENT)
        if (bits.size > 5 && bits[5]) out.add(KeyUsage.KEY_CERT_SIGN)
        if (bits.size > 6 && bits[6]) out.add(KeyUsage.CRL_SIGN)
        if (bits.size > 7 && bits[7]) out.add(KeyUsage.ENCIPHER_ONLY)
        if (bits.size > 8 && bits[8]) out.add(KeyUsage.DECIPHER_ONLY)
        return out
    }
}

internal object ExtendedKeyUsageExtractor {
    fun extractOids(cert: X509Certificate): List<String> = cert.extendedKeyUsage ?: emptyList()

    fun nameFor(oid: String): String = when (oid) {
        "1.3.6.1.5.5.7.3.1" -> "id-kp-serverAuth"
        "1.3.6.1.5.5.7.3.2" -> "id-kp-clientAuth"
        "1.3.6.1.5.5.7.3.3" -> "id-kp-codeSigning"
        "1.3.6.1.5.5.7.3.4" -> "id-kp-emailProtection"
        "1.3.6.1.5.5.7.3.8" -> "id-kp-timeStamping"
        "1.3.6.1.5.5.7.3.9" -> "id-kp-OCSPSigning"
        "1.3.6.1.4.1.311.10.3.4" -> "MS-EFS"
        "1.3.6.1.5.2.3.4" -> "id-pkinit-KPClientAuth"
        "1.3.6.1.5.2.3.5" -> "id-pkinit-KPKdc"
        "2.5.29.37.0" -> "anyExtendedKeyUsage"
        else -> oid
    }
}

internal object BasicConstraintsExtractor {
    fun extract(cert: X509Certificate): BasicConstraints? {
        val bc = cert.getExtensionValue(Extension.basicConstraints.id) ?: return null
        val parsed = org.bouncycastle.asn1.ASN1OctetString.getInstance(bc).octets
        val bcAsn = org.bouncycastle.asn1.x509.BasicConstraints.getInstance(parsed)
        val pathLen = if (bcAsn.isCA) bcAsn.pathLenConstraint?.toInt() else null
        return BasicConstraints(isCa = bcAsn.isCA, pathLenConstraint = pathLen)
    }
}

internal object AiaExtractor {
    fun extract(holder: X509CertificateHolder): AuthorityInfoAccess? {
        val ext = holder.getExtension(Extension.authorityInfoAccess) ?: return null
        val aia = org.bouncycastle.asn1.x509.AuthorityInformationAccess.getInstance(ext.parsedValue)
        val ocsp = mutableListOf<String>()
        val issuer = mutableListOf<String>()
        for (descr in aia.accessDescriptions) {
            val url = descr.accessLocation.name.toString()
            when (descr.accessMethod.id) {
                "1.3.6.1.5.5.7.48.1" -> ocsp.add(url)        // id-ad-ocsp
                "1.3.6.1.5.5.7.48.2" -> issuer.add(url)      // id-ad-caIssuers
            }
        }
        return AuthorityInfoAccess(ocsp, issuer)
    }
}

internal object CrlDpExtractor {
    fun extract(holder: X509CertificateHolder): List<String> {
        val ext = holder.getExtension(Extension.cRLDistributionPoints) ?: return emptyList()
        val dps = org.bouncycastle.asn1.x509.CRLDistPoint.getInstance(ext.parsedValue)
        val urls = mutableListOf<String>()
        for (dp in dps.distributionPoints) {
            val name = dp.distributionPoint?.name ?: continue
            if (name is org.bouncycastle.asn1.x509.GeneralNames) {
                for (gn in name.names) {
                    if (gn.tagNo == org.bouncycastle.asn1.x509.GeneralName.uniformResourceIdentifier) {
                        urls.add(gn.name.toString())
                    }
                }
            }
        }
        return urls
    }
}

internal object CertificatePoliciesExtractor {
    fun extract(holder: X509CertificateHolder): List<String> {
        val ext = holder.getExtension(Extension.certificatePolicies) ?: return emptyList()
        val pi = org.bouncycastle.asn1.x509.CertificatePolicies.getInstance(ext.parsedValue)
        return pi.policyInformation.map { it.policyIdentifier.id }
    }
}

internal object NameConstraintsExtractor {
    fun extract(holder: X509CertificateHolder): NameConstraintsInfo? {
        val ext = holder.getExtension(Extension.nameConstraints) ?: return null
        val nc = org.bouncycastle.asn1.x509.NameConstraints.getInstance(ext.parsedValue)
        val permitted = nc.permittedSubtrees?.map { it.base.name.toString() } ?: emptyList()
        val excluded = nc.excludedSubtrees?.map { it.base.name.toString() } ?: emptyList()
        return NameConstraintsInfo(permitted, excluded)
    }
}

internal object SctExtractor {
    private val OID_PRECERT_SCTS = ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")
    fun extract(holder: X509CertificateHolder): List<SctInfo> {
        // Full RFC 6962 SCT parsing is non-trivial; we only flag presence + count for now.
        // Detailed parsing is added in MS D.
        val ext = holder.getExtension(OID_PRECERT_SCTS) ?: return emptyList()
        // Mark presence by returning a placeholder SCT entry — actual log_id parsing is MS D.
        return listOf(
            SctInfo(
                version = 1,
                logIdHex = "<parsing-deferred-to-MS-D>",
                timestamp = Instant.EPOCH,
                signatureAlgorithm = "embedded"
            )
        )
    }
}

internal object TlsFeatureExtractor {
    private val OID_TLS_FEATURE = ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.24")
    fun extract(holder: X509CertificateHolder): List<Int> {
        val ext = holder.getExtension(OID_TLS_FEATURE) ?: return emptyList()
        val seq = org.bouncycastle.asn1.ASN1Sequence.getInstance(ext.parsedValue)
        return (0 until seq.size()).mapNotNull {
            (seq.getObjectAt(it) as? org.bouncycastle.asn1.ASN1Integer)?.value?.toInt()
        }
    }
}
