package io.safebyte.tlsinspector.probes

import io.safebyte.tlsinspector.CipherFlag
import io.safebyte.tlsinspector.CipherGrade
import io.safebyte.tlsinspector.CipherSuiteResult
import io.safebyte.tlsinspector.HandshakeParams
import io.safebyte.tlsinspector.HandshakeResult
import io.safebyte.tlsinspector.ProbeContext
import io.safebyte.tlsinspector.ProtocolStatus
import io.safebyte.tlsinspector.TlsConfig
import io.safebyte.tlsinspector.TlsConfidence
import io.safebyte.tlsinspector.TlsConnector
import io.safebyte.tlsinspector.TlsProtocol
import io.safebyte.tlsinspector.TlsScanResult
import io.safebyte.tlsinspector.TlsSeverity
import io.safebyte.tlsinspector.reporting.TlsFinding
import org.bouncycastle.tls.ProtocolVersion

class CipherSuiteEnumerationProbe : TlsProbe {
    override val id = TlsConfig.PROBE_CIPHER_ENUM
    override val displayName = "Cipher Suite Enumeration"
    override val kind = ProbeKind.INFORMATIONAL

    override fun run(ctx: ProbeContext, result: TlsScanResult): List<TlsFinding> {
        val findings = mutableListOf<TlsFinding>()
        val connector = TlsConnector(ctx)

        for ((proto, status) in result.protocolsOffered.toMap()) {
            if (ctx.cancelled()) break
            if (status != ProtocolStatus.OFFERED) continue
            // Skip SSLv2 / SSLv3 — BCTLS refuses to enumerate ciphers for those (engine-level
            // disabled). Their ciphersByProtocol entries are pre-populated by
            // ProtocolEnumerationProbe.probeSSLv2 / probeSSLv3 via raw socket.
            if (proto == TlsProtocol.SSL_2_0 || proto == TlsProtocol.SSL_3_0) continue
            val bcVersion = bcProtocolVersion(proto) ?: continue
            val accepted = mutableListOf<CipherSuiteResult>()
            val candidates = TlsConfig.ALL_CIPHER_SUITES.take(TlsConfig.MAX_CIPHERS_PER_PROTOCOL)

            for (cipher in candidates) {
                if (ctx.cancelled()) break
                val params = HandshakeParams.forCipher(bcVersion, cipher, ctx.sni)
                val res = connector.attempt(params)
                if (res is HandshakeResult.Success && res.negotiatedCipherSuite == cipher) {
                    accepted += classify(cipher)
                    ctx.api.logging().logToOutput("[TLS Audit] $id: ${proto.displayName} accepts ${TlsConfig.getCipherSuiteName(cipher)}")
                }
            }
            result.ciphersByProtocol[proto] = accepted

            // Tiered cipher findings — emit by severity, most severe first, use continue to avoid stacking
            for (c in accepted) {
                val protoTag = proto.displayName
                val nameTag = c.name
                // Tier 1 (HIGH): categorically broken — NULL, anon, EXPORT, RC4
                if (CipherFlag.NULL_CIPHER in c.flags) {
                    findings += TlsFinding(
                        id = "CIPHER_HIGH_${nameTag}_${proto.name}",
                        title = "NULL Cipher Offered: $nameTag",
                        severity = TlsSeverity.HIGH,
                        confidence = TlsConfidence.FIRM,
                        descriptionHtml = "<p>Server offers NULL cipher <code>$nameTag</code> on $protoTag. " +
                            "NULL ciphers provide no encryption whatsoever — traffic is completely exposed.</p>"
                    )
                    continue
                }
                if (CipherFlag.ANON_KX in c.flags) {
                    findings += TlsFinding(
                        id = "CIPHER_HIGH_${nameTag}_${proto.name}",
                        title = "Anonymous KX Cipher Offered: $nameTag",
                        severity = TlsSeverity.HIGH,
                        confidence = TlsConfidence.FIRM,
                        descriptionHtml = "<p>Server offers anonymous key-exchange cipher <code>$nameTag</code> on $protoTag. " +
                            "No server authentication is performed — connections are trivially MitM'd.</p>"
                    )
                    continue
                }
                if (CipherFlag.EXPORT_GRADE in c.flags) {
                    findings += TlsFinding(
                        id = "CIPHER_HIGH_${nameTag}_${proto.name}",
                        title = "EXPORT Cipher Offered: $nameTag",
                        severity = TlsSeverity.HIGH,
                        confidence = TlsConfidence.FIRM,
                        descriptionHtml = "<p>Server offers EXPORT-grade cipher <code>$nameTag</code> on $protoTag. " +
                            "EXPORT ciphers use intentionally weak key material (40–56 bit) and are trivially broken.</p>"
                    )
                    continue
                }
                if (CipherFlag.RC4 in c.flags) {
                    findings += TlsFinding(
                        id = "CIPHER_HIGH_${nameTag}_${proto.name}",
                        title = "RC4 Cipher Offered: $nameTag",
                        severity = TlsSeverity.HIGH,
                        confidence = TlsConfidence.FIRM,
                        descriptionHtml = "<p>Server offers RC4 stream cipher <code>$nameTag</code> on $protoTag. " +
                            "RC4 has well-known statistical biases (BEAST, Bar-Mitzvah, NOMORE) and is prohibited by RFC 7465.</p>",
                        references = listOf("https://datatracker.ietf.org/doc/html/rfc7465")
                    )
                    continue
                }
                // Tier 2 (MEDIUM): deprecated — 3DES or MD5 MAC
                if (CipherFlag.TRIPLE_DES_64BIT_BLOCK in c.flags) {
                    findings += TlsFinding(
                        id = "CIPHER_MEDIUM_${nameTag}_${proto.name}",
                        title = "3DES Cipher Offered: $nameTag",
                        severity = TlsSeverity.MEDIUM,
                        confidence = TlsConfidence.FIRM,
                        descriptionHtml = "<p>Server offers 3DES cipher <code>$nameTag</code> on $protoTag. " +
                            "3DES has a 64-bit block size, making it vulnerable to Sweet32 birthday attacks in long sessions. " +
                            "Deprecated by NIST SP 800-131A.</p>",
                        references = listOf("https://sweet32.info/")
                    )
                    continue
                }
                if (c.mac == "MD5") {
                    findings += TlsFinding(
                        id = "CIPHER_MEDIUM_${nameTag}_${proto.name}",
                        title = "MD5 MAC Cipher Offered: $nameTag",
                        severity = TlsSeverity.MEDIUM,
                        confidence = TlsConfidence.FIRM,
                        descriptionHtml = "<p>Server offers cipher <code>$nameTag</code> with MD5 MAC on $protoTag. " +
                            "MD5 is collision-vulnerable and deprecated in TLS authentication contexts.</p>"
                    )
                    continue
                }
                // Tier 3 (LOW): legacy but not broken — can stack
                if (c.keyExchange == "RSA" && CipherFlag.FORWARD_SECRECY !in c.flags) {
                    findings += TlsFinding(
                        id = "CIPHER_LOW_no_fs_${nameTag}_${proto.name}",
                        title = "No Forward Secrecy: $nameTag",
                        severity = TlsSeverity.LOW,
                        confidence = TlsConfidence.FIRM,
                        descriptionHtml = "<p>Cipher <code>$nameTag</code> on $protoTag uses static RSA key exchange. " +
                            "Compromise of the server's private key retroactively decrypts all recorded sessions.</p>"
                    )
                }
                if (CipherFlag.CBC_NO_AEAD in c.flags && CipherFlag.AEAD !in c.flags) {
                    findings += TlsFinding(
                        id = "CIPHER_LOW_cbc_${nameTag}_${proto.name}",
                        title = "CBC Mode Without AEAD: $nameTag",
                        severity = TlsSeverity.LOW,
                        confidence = TlsConfidence.FIRM,
                        descriptionHtml = "<p>Cipher <code>$nameTag</code> on $protoTag uses CBC mode without authenticated encryption. " +
                            "Padding oracle attacks (Lucky13, POODLE-TLS) may apply in certain configurations.</p>"
                    )
                }
            }
        }
        synchronized(result) { result.findings += findings }
        return findings
    }

    private fun bcProtocolVersion(p: TlsProtocol): ProtocolVersion? = when (p) {
        TlsProtocol.SSL_3_0 -> ProtocolVersion.SSLv3
        TlsProtocol.TLS_1_0 -> ProtocolVersion.TLSv10
        TlsProtocol.TLS_1_1 -> ProtocolVersion.TLSv11
        TlsProtocol.TLS_1_2 -> ProtocolVersion.TLSv12
        TlsProtocol.TLS_1_3 -> ProtocolVersion.TLSv13
        else -> null
    }

    private fun classify(cipher: Int): CipherSuiteResult {
        val name = TlsConfig.getCipherSuiteName(cipher)
        val flags = mutableSetOf<CipherFlag>()
        if (name.contains("NULL")) flags += CipherFlag.NULL_CIPHER
        if (name.contains("anon", ignoreCase = true)) flags += CipherFlag.ANON_KX
        if (name.contains("EXPORT")) flags += CipherFlag.EXPORT_GRADE
        if (name.contains("RC4")) flags += CipherFlag.RC4
        if (name.contains("3DES") || name.contains("DES_CBC")) flags += CipherFlag.TRIPLE_DES_64BIT_BLOCK
        if (name.contains("CBC") && !name.contains("GCM") && !name.contains("CCM")) flags += CipherFlag.CBC_NO_AEAD
        if (name.contains("ECDHE") || name.contains("DHE")) flags += CipherFlag.FORWARD_SECRECY
        if (name.contains("GCM") || name.contains("CCM") || name.contains("CHACHA20")) flags += CipherFlag.AEAD

        val grade = when {
            CipherFlag.NULL_CIPHER in flags || CipherFlag.ANON_KX in flags || CipherFlag.EXPORT_GRADE in flags -> CipherGrade.INSECURE
            CipherFlag.RC4 in flags || CipherFlag.TRIPLE_DES_64BIT_BLOCK in flags -> CipherGrade.WEAK
            CipherFlag.AEAD in flags && CipherFlag.FORWARD_SECRECY in flags -> CipherGrade.STRONG
            CipherFlag.AEAD in flags -> CipherGrade.ACCEPTABLE
            else -> CipherGrade.WEAK
        }
        return CipherSuiteResult(
            name = name,
            openSslName = null,
            keyExchange = if ("ECDHE" in name) "ECDHE" else if ("DHE" in name) "DHE" else "RSA",
            authentication = if ("ECDSA" in name) "ECDSA" else "RSA",
            encryption = name.substringAfter("_WITH_", name).substringBeforeLast("_"),
            mac = name.substringAfterLast("_"),
            grade = grade,
            flags = flags
        )
    }
}
