package io.safebyte.tlsinspector.probes

import io.safebyte.tlsinspector.ClientHelloBuilder
import io.safebyte.tlsinspector.HandshakeParams
import io.safebyte.tlsinspector.HandshakeResult
import io.safebyte.tlsinspector.ProbeContext
import io.safebyte.tlsinspector.ProtocolStatus
import io.safebyte.tlsinspector.RawProbeOutcome
import io.safebyte.tlsinspector.TlsConfig
import io.safebyte.tlsinspector.TlsConfidence
import io.safebyte.tlsinspector.TlsConnector
import io.safebyte.tlsinspector.TlsProtocol
import io.safebyte.tlsinspector.TlsScanResult
import io.safebyte.tlsinspector.TlsSeverity
import io.safebyte.tlsinspector.reporting.TlsFinding
import org.bouncycastle.tls.ProtocolVersion
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.Socket

class ProtocolEnumerationProbe : TlsProbe {
    override val id = TlsConfig.PROBE_PROTOCOL_ENUM
    override val displayName = "Protocol Version Enumeration"
    override val kind = ProbeKind.INFORMATIONAL

    override fun run(ctx: ProbeContext, result: TlsScanResult): List<TlsFinding> {
        val findings = mutableListOf<TlsFinding>()
        val connector = TlsConnector(ctx)

        for (proto in TlsProtocol.entries) {
            if (ctx.cancelled()) break
            if (proto == TlsProtocol.SSL_2_0) {
                // BCTLS does not support SSLv2. Send a raw SSLv2 ClientHello via socket.
                // RST / EOF = NOT_OFFERED (normal modern-server response). TCP-connect failure = ERROR.
                result.protocolsOffered[proto] = probeSSLv2(ctx)
                ctx.api.logging().logToOutput("[TLS Audit] $id: ${proto.displayName} → ${result.protocolsOffered[proto]}")
                continue
            }
            if (proto == TlsProtocol.SSL_3_0) {
                // BCTLS 1.79 refuses to send SSLv3 ClientHello at the engine level. Bypass by
                // building a raw SSLv3 ClientHello via ClientHelloBuilder and sending via raw socket.
                result.protocolsOffered[proto] = probeSSLv3(ctx, connector, result)
                ctx.api.logging().logToOutput("[TLS Audit] $id: ${proto.displayName} → ${result.protocolsOffered[proto]}")
                continue
            }
            val bcVersion = bcProtocolVersion(proto) ?: continue
            val ciphers = if (proto == TlsProtocol.TLS_1_3) TlsConfig.DEFAULT_CIPHER_SUITES_MODERN else TlsConfig.ALL_CIPHER_SUITES
            val params = HandshakeParams.forVersion(bcVersion, ctx.sni, ciphers)
            val res = connector.attempt(params)
            val offered = res is HandshakeResult.Success && res.negotiatedProtocol == bcVersion
            result.protocolsOffered[proto] = if (offered) ProtocolStatus.OFFERED else ProtocolStatus.NOT_OFFERED
            ctx.api.logging().logToOutput("[TLS Audit] $id: ${proto.displayName} → ${result.protocolsOffered[proto]}")
        }

        // Emit findings for deprecated protocols
        if (result.protocolsOffered[TlsProtocol.TLS_1_0] == ProtocolStatus.OFFERED)
            findings += deprecatedFinding("tls10_offered", "TLS 1.0 Offered", TlsSeverity.HIGH)
        if (result.protocolsOffered[TlsProtocol.TLS_1_1] == ProtocolStatus.OFFERED)
            findings += deprecatedFinding("tls11_offered", "TLS 1.1 Offered", TlsSeverity.MEDIUM)
        if (result.protocolsOffered[TlsProtocol.SSL_3_0] == ProtocolStatus.OFFERED)
            findings += deprecatedFinding("sslv3_offered", "SSLv3 Offered", TlsSeverity.CRITICAL)
        if (result.protocolsOffered[TlsProtocol.SSL_2_0] == ProtocolStatus.OFFERED)
            findings += deprecatedFinding("sslv2_offered", "SSLv2 Offered", TlsSeverity.CRITICAL)

        if (result.protocolsOffered[TlsProtocol.TLS_1_2] != ProtocolStatus.OFFERED &&
            result.protocolsOffered[TlsProtocol.TLS_1_3] != ProtocolStatus.OFFERED) {
            findings += TlsFinding(
                id = "$id:no_modern_tls",
                title = "No Modern TLS (1.2 or 1.3)",
                severity = TlsSeverity.HIGH,
                confidence = TlsConfidence.FIRM,
                descriptionHtml = "<p>Server does not offer TLS 1.2 or TLS 1.3. All connections use deprecated protocols.</p>"
            )
        }

        // C4: Emit finding when TLS 1.3 is absent — LOW severity (server should modernize)
        if (result.protocolsOffered[TlsProtocol.TLS_1_3] != ProtocolStatus.OFFERED) {
            findings += TlsFinding(
                id = "$id:no_tls13",
                title = "TLS 1.3 Not Supported",
                severity = TlsSeverity.LOW,
                confidence = TlsConfidence.FIRM,
                descriptionHtml = "<p>Server does not offer TLS 1.3. TLS 1.3 eliminates several legacy handshake attacks, " +
                    "removes non-AEAD cipher suites, and is required for optimal performance (0-RTT). " +
                    "Configure the server to enable TLS 1.3 alongside TLS 1.2.</p>",
                references = listOf("https://datatracker.ietf.org/doc/html/rfc8446")
            )
        }

        // Merge probe findings into the shared scan result so the runner sees them
        synchronized(result) { result.findings += findings }
        return findings
    }

    private fun bcProtocolVersion(p: TlsProtocol): ProtocolVersion? = when (p) {
        TlsProtocol.SSL_3_0 -> ProtocolVersion.SSLv3
        TlsProtocol.TLS_1_0 -> ProtocolVersion.TLSv10
        TlsProtocol.TLS_1_1 -> ProtocolVersion.TLSv11
        TlsProtocol.TLS_1_2 -> ProtocolVersion.TLSv12
        TlsProtocol.TLS_1_3 -> ProtocolVersion.TLSv13
        TlsProtocol.SSL_2_0 -> null  // handled via probeSSLv2()
    }

    /**
     * Probes for SSLv2 support by sending a raw SSLv2 ClientHello over a plain TCP socket.
     * SSLv2 is not supported by BCTLS, so we implement the minimal wire format here.
     *
     * SSLv2 ClientHello (minimal):
     *   - 2-byte length header: MSB set (0x80) + low byte = remaining length
     *   - MSG_CLIENT_HELLO (0x01)
     *   - Version bytes: 0x00 0x02
     *   - CipherSpec length: 0x00 0x03 (3 bytes = 1 cipher)
     *   - Session ID length: 0x00 0x00
     *   - Challenge length: 0x00 0x10 (16 bytes)
     *   - CipherSpec: 0x07 0x00 0xC0 (SSL_CK_DES_192_EDE3_CBC_WITH_MD5)
     *   - Challenge: 16 random bytes
     *
     * If server responds with 0x80 (length-byte MSB set) or 0x00 + 0x02 (SSLv2 record),
     * SSLv2 is OFFERED. Any other response, RST, or EOF = NOT_OFFERED. TCP failure = ERROR.
     */
    private fun probeSSLv2(ctx: ProbeContext): ProtocolStatus {
        val timeoutMs = ctx.budget.handshakeTimeout.toMillis().toInt()
        // Minimal SSLv2 ClientHello — 2-byte header + 19 bytes body = 21 bytes total
        val challenge = ByteArray(16) { (it + 1).toByte() }
        val body = byteArrayOf(
            0x01.toByte(),              // MSG_CLIENT_HELLO
            0x00.toByte(), 0x02.toByte(), // version: SSLv2
            0x00.toByte(), 0x03.toByte(), // cipher_specs_length: 3
            0x00.toByte(), 0x00.toByte(), // session_id_length: 0
            0x00.toByte(), 0x10.toByte(), // challenge_length: 16
            0x07.toByte(), 0x00.toByte(), 0xC0.toByte(), // SSL_CK_DES_192_EDE3_CBC_WITH_MD5
            *challenge
        )
        // SSLv2 2-byte header: high bit set + message length
        val header = byteArrayOf(
            (0x80 or (body.size shr 8)).toByte(),
            (body.size and 0xFF).toByte()
        )
        val clientHello = header + body

        var socket: Socket? = null
        return try {
            socket = Socket()
            socket.tcpNoDelay = true
            socket.soTimeout = timeoutMs
            try {
                socket.connect(InetSocketAddress(ctx.host, ctx.port), timeoutMs)
            } catch (_: Exception) {
                return ProtocolStatus.ERROR  // TCP connect failure = cannot determine
            }
            socket.getOutputStream().write(clientHello)
            socket.getOutputStream().flush()

            val buf = ByteArray(5)
            val read = try {
                readAtLeast(socket.getInputStream(), buf, 1)
            } catch (_: Exception) {
                0  // RST, EOF, timeout — not offered
            }
            if (read <= 0) return ProtocolStatus.NOT_OFFERED

            // SSLv2 ServerHello: first byte is 0x80 (length MSB set) for short records,
            // or 0x00 for a 3-byte header where second byte is 0x00 and third is type 0x04.
            val firstByte = buf[0].toInt() and 0xFF
            when {
                firstByte == 0x80 -> ProtocolStatus.OFFERED   // SSLv2 short-header server response
                firstByte == 0x00 && read >= 3 && (buf[2].toInt() and 0xFF) == 0x04 -> ProtocolStatus.OFFERED
                else -> ProtocolStatus.NOT_OFFERED
            }
        } catch (_: Exception) {
            ProtocolStatus.NOT_OFFERED  // any other I/O error — best-effort not offered
        } finally {
            try { socket?.close() } catch (_: Exception) { }
        }
    }

    /**
     * Probes SSLv3 by sending a raw ClientHello via socket. BCTLS 1.79 internally
     * disables SSLv3 even when ProtocolVersion.SSLv3 is requested; the only reliable
     * way to detect SSLv3 support is to bypass BCTLS entirely.
     *
     * Builds a SSLv3 ClientHello via ClientHelloBuilder with SSLv3-compatible RSA + AES-CBC
     * cipher suites, sends it over a raw TCP socket, and inspects the first response bytes:
     *   - Record type 0x16 (Handshake) + version 0x0300 → ServerHello sent → OFFERED
     *   - Record type 0x15 (Alert) → server rejected → NOT_OFFERED
     *   - No data / TCP error → NOT_OFFERED
     */
    private fun probeSSLv3(ctx: ProbeContext, connector: TlsConnector, result: TlsScanResult): ProtocolStatus {
        // SSLv3-compatible cipher suites (no AEAD, no ECDHE — those are TLS 1.0+ only)
        val sslv3Ciphers = listOf(
            0x002F,  // TLS_RSA_WITH_AES_128_CBC_SHA
            0x0035,  // TLS_RSA_WITH_AES_256_CBC_SHA
            0x000A,  // TLS_RSA_WITH_3DES_EDE_CBC_SHA
            0x0005,  // TLS_RSA_WITH_RC4_128_SHA
            0x0004,  // TLS_RSA_WITH_RC4_128_MD5
        )
        return try {
            val clientHello = ClientHelloBuilder.build(
                version = TlsProtocol.SSL_3_0,
                sni = ctx.sni,
                cipherSuites = sslv3Ciphers,
            )
            val outcome = connector.probeRawAfterHello(clientHello, ByteArray(0))
            if (outcome !is RawProbeOutcome.Ok || outcome.handshakePhase.size < 6) {
                return ProtocolStatus.NOT_OFFERED
            }
            val resp = outcome.handshakePhase
            val recType = resp[0].toInt() and 0xFF
            val recMajor = resp[1].toInt() and 0xFF
            val recMinor = resp[2].toInt() and 0xFF
            // Record type 0x16 (Handshake) AND record version 0x0300 (SSLv3) → OFFERED
            if (recType != 0x16 || recMajor != 0x03 || recMinor != 0x00) {
                return ProtocolStatus.NOT_OFFERED
            }

            // Server accepted SSLv3 — extract negotiated cipher from ServerHello and populate
            // result.ciphersByProtocol[SSL_3_0] so downstream probes (POODLE) can see it.
            // ServerHello body layout starting at handshake offset 4 (record offset 9):
            //   2 bytes version + 32 bytes random + 1+N session_id_len/data + 2 bytes cipher_suite
            val cipherCode = parseServerHelloCipherSuite(resp)
            if (cipherCode != null) {
                val cipher = io.safebyte.tlsinspector.CipherSuiteResult(
                    name = io.safebyte.tlsinspector.TlsConfig.getCipherSuiteName(cipherCode) ?: "0x${"%04X".format(cipherCode)}",
                    openSslName = null,
                    keyExchange = "RSA",
                    authentication = "RSA",
                    encryption = encryptionFromCipher(cipherCode),
                    mac = "SHA",
                    grade = io.safebyte.tlsinspector.CipherGrade.WEAK,
                    flags = flagsFromCipher(cipherCode),
                )
                synchronized(result) {
                    val existing = result.ciphersByProtocol[io.safebyte.tlsinspector.TlsProtocol.SSL_3_0] ?: emptyList()
                    result.ciphersByProtocol[io.safebyte.tlsinspector.TlsProtocol.SSL_3_0] = existing + cipher
                }
            }
            ProtocolStatus.OFFERED
        } catch (_: Exception) {
            ProtocolStatus.NOT_OFFERED
        }
    }

    /** Parse the cipher_suite (2 bytes) from a ServerHello in raw record bytes. */
    private fun parseServerHelloCipherSuite(record: ByteArray): Int? {
        // Record header: 5 bytes. Handshake header: 4 bytes (type + 24-bit len).
        // ServerHello body: version(2) + random(32) + session_id_len(1) + session_id(N) + cipher_suite(2)
        if (record.size < 5 + 4 + 2 + 32 + 1 + 2) return null
        val sessionIdLen = record[5 + 4 + 2 + 32].toInt() and 0xFF
        val cipherOffset = 5 + 4 + 2 + 32 + 1 + sessionIdLen
        if (cipherOffset + 2 > record.size) return null
        return ((record[cipherOffset].toInt() and 0xFF) shl 8) or (record[cipherOffset + 1].toInt() and 0xFF)
    }

    private fun encryptionFromCipher(code: Int): String = when (code) {
        0x002F -> "AES_128_CBC"
        0x0035 -> "AES_256_CBC"
        0x000A -> "3DES_EDE_CBC"
        0x0005 -> "RC4_128"
        0x0004 -> "RC4_128"
        else -> "UNKNOWN"
    }

    private fun flagsFromCipher(code: Int): Set<io.safebyte.tlsinspector.CipherFlag> {
        val flags = mutableSetOf<io.safebyte.tlsinspector.CipherFlag>()
        // CBC mode without AEAD on SSLv3 → POODLE applies
        if (code in setOf(0x002F, 0x0035, 0x000A)) flags.add(io.safebyte.tlsinspector.CipherFlag.CBC_NO_AEAD)
        if (code in setOf(0x0005, 0x0004)) flags.add(io.safebyte.tlsinspector.CipherFlag.RC4)
        if (code == 0x000A) flags.add(io.safebyte.tlsinspector.CipherFlag.TRIPLE_DES_64BIT_BLOCK)
        return flags
    }

    private fun readAtLeast(input: InputStream, buf: ByteArray, min: Int): Int {
        var total = 0
        while (total < min && total < buf.size) {
            val n = input.read(buf, total, buf.size - total)
            if (n < 0) break
            total += n
        }
        return total
    }

    private fun deprecatedFinding(key: String, title: String, sev: TlsSeverity) = TlsFinding(
        id = "$id:$key",
        title = title,
        severity = sev,
        confidence = TlsConfidence.FIRM,
        descriptionHtml = "<p>The server offered a deprecated TLS protocol version.</p>",
        references = listOf("https://datatracker.ietf.org/doc/html/rfc8996")
    )
}
