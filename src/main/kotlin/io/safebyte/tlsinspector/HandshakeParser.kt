package io.safebyte.tlsinspector

import java.math.BigInteger
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.interfaces.RSAPublicKey

/**
 * Minimal TLS server-response parser for raw-socket probes.
 *
 * Parses the bytes returned by the server after we send a raw ClientHello.
 * Does NOT implement a full TLS state machine — only extracts the fields
 * that vulnerability probes need:
 *  - Alert type/description (is the server rejecting our ClientHello?)
 *  - Negotiated protocol version from ServerHello
 *  - Selected cipher suite from ServerHello
 *  - DH ServerKeyExchange prime (p), for Logjam / weak-DH detection
 *  - Heartbeat extension presence in ServerHello extensions
 *
 * All parse methods return null on any structural inconsistency rather than
 * throwing, so probes can treat null as "could not parse" and fall back
 * gracefully.
 *
 * All multi-byte integers are big-endian per RFC 5246.
 */
class HandshakeParser(private val data: ByteArray) {

    companion object {
        /**
         * Convenience: parse the ServerHello compression byte from raw bytes.
         * Returns null if no ServerHello is found or the data is too short.
         */
        fun serverHelloCompression(bytes: ByteArray): Int? =
            HandshakeParser(bytes).parseServerHello()?.compressionMethod

        /**
         * Convenience: extract the first alert description code from raw bytes.
         * Returns null if the data is not an alert record.
         */
        fun firstAlertDescription(bytes: ByteArray): Int? =
            HandshakeParser(bytes).parseAlert()?.description

        /**
         * Convenience: extract DH prime from raw ServerKeyExchange bytes.
         * Returns null if no DHE ServerKeyExchange is found.
         */
        fun extractDhPrimeFromServerKeyExchange(bytes: ByteArray): DhParams? =
            HandshakeParser(bytes).parseDhServerKeyExchange()

        // ─────────────────────────────────────────────────────────────────────────
        // MS C — new static helpers ported from validated standalone
        // ─────────────────────────────────────────────────────────────────────────

        /**
         * Extract RSA public key (modulus, publicExponent) from the first cert in a DER chain.
         * Returns null if the cert is not RSA or cannot be parsed.
         */
        fun extractRsaPublicKey(certChainDer: List<ByteArray>): Pair<BigInteger, BigInteger>? {
            if (certChainDer.isEmpty()) return null
            return try {
                val cf = CertificateFactory.getInstance("X.509")
                val cert = cf.generateCertificate(certChainDer[0].inputStream())
                val pubKey = cert.publicKey
                if (pubKey is RSAPublicKey) {
                    Pair(pubKey.modulus, pubKey.publicExponent)
                } else null
            } catch (_: Exception) { null }
        }

        /**
         * Full DH parameter set from a raw ServerKeyExchange body (after the 4-byte handshake header).
         * Used by Raccoon probe to compare Ys values across handshakes.
         */
        data class DhParamsFull(
            val p: BigInteger,
            val g: BigInteger,
            val ys: BigInteger,
            val ysRaw: ByteArray   // raw Ys bytes for equality comparison
        )

        fun parseServerKeyExchangeDhFull(skeBody: ByteArray): DhParamsFull? {
            return try {
                var pos = 0
                fun readField(): ByteArray {
                    val len = ((skeBody[pos].toInt() and 0xFF) shl 8) or (skeBody[pos+1].toInt() and 0xFF)
                    val bytes = skeBody.copyOfRange(pos + 2, pos + 2 + len)
                    pos += 2 + len
                    return bytes
                }
                val pBytes  = readField()
                val gBytes  = readField()
                val ysBytes = readField()
                DhParamsFull(
                    p     = BigInteger(1, pBytes),
                    g     = BigInteger(1, gBytes),
                    ys    = BigInteger(1, ysBytes),
                    ysRaw = ysBytes
                )
            } catch (_: Exception) { null }
        }

        /**
         * Walk TLS records in [records], find the first ServerKeyExchange (handshake type 0x0C),
         * and return its body bytes (after the 4-byte handshake header).
         */
        fun findServerKeyExchangeBody(records: ByteArray): ByteArray? {
            var offset = 0
            while (offset + 5 <= records.size) {
                val rt  = records[offset].toInt() and 0xFF
                val len = ((records[offset+3].toInt() and 0xFF) shl 8) or (records[offset+4].toInt() and 0xFF)
                if (rt == 0x16) {
                    var hPos = offset + 5
                    val hEnd = (offset + 5 + len).coerceAtMost(records.size)
                    while (hPos + 4 <= hEnd) {
                        val msgType = records[hPos].toInt() and 0xFF
                        val msgLen  = ((records[hPos+1].toInt() and 0xFF) shl 16) or
                                      ((records[hPos+2].toInt() and 0xFF) shl 8)  or
                                       (records[hPos+3].toInt() and 0xFF)
                        if (msgType == 0x0C) {
                            val bodyStart = hPos + 4
                            val bodyEnd   = (bodyStart + msgLen).coerceAtMost(hEnd)
                            return records.copyOfRange(bodyStart, bodyEnd)
                        }
                        hPos += 4 + msgLen
                    }
                }
                if (len < 0) break
                offset += 5 + len
            }
            return null
        }

        /**
         * Walk TLS records in [records], find the Certificate handshake message (type 0x0B),
         * and return a list of DER-encoded certificate byte arrays.
         */
        fun extractCertChain(records: ByteArray): List<ByteArray> {
            var offset = 0
            while (offset + 5 <= records.size) {
                val rt  = records[offset].toInt() and 0xFF
                val len = ((records[offset+3].toInt() and 0xFF) shl 8) or (records[offset+4].toInt() and 0xFF)
                if (rt == 0x16) {
                    var hPos = offset + 5
                    val hEnd = (offset + 5 + len).coerceAtMost(records.size)
                    while (hPos + 4 <= hEnd) {
                        val msgType = records[hPos].toInt() and 0xFF
                        val msgLen  = ((records[hPos+1].toInt() and 0xFF) shl 16) or
                                      ((records[hPos+2].toInt() and 0xFF) shl 8)  or
                                       (records[hPos+3].toInt() and 0xFF)
                        if (msgType == 0x0B) {
                            val bodyStart = hPos + 4
                            val bodyEnd   = (bodyStart + msgLen).coerceAtMost(hEnd)
                            return parseCertificateList(records, bodyStart, bodyEnd)
                        }
                        hPos += 4 + msgLen
                    }
                }
                if (len < 0) break
                offset += 5 + len
            }
            return emptyList()
        }

        private fun parseCertificateList(buf: ByteArray, start: Int, end: Int): List<ByteArray> {
            if (start + 3 > end) return emptyList()
            val listLen = ((buf[start].toInt() and 0xFF) shl 16) or
                          ((buf[start+1].toInt() and 0xFF) shl 8) or
                           (buf[start+2].toInt() and 0xFF)
            val certs = mutableListOf<ByteArray>()
            var pos = start + 3
            val listEnd = (start + 3 + listLen).coerceAtMost(end)
            while (pos + 3 <= listEnd) {
                val certLen = ((buf[pos].toInt() and 0xFF) shl 16) or
                              ((buf[pos+1].toInt() and 0xFF) shl 8) or
                               (buf[pos+2].toInt() and 0xFF)
                pos += 3
                if (certLen <= 0 || pos + certLen > listEnd) break
                certs += buf.copyOfRange(pos, pos + certLen)
                pos += certLen
            }
            return certs
        }
    }


    // -------------------------------------------------------------------------
    // TLS Record Layer
    // -------------------------------------------------------------------------

    /** True if the data starts with a valid TLS handshake record header. */
    val hasHandshakeRecord: Boolean
        get() = data.size >= 5 && data[0] == 0x16.toByte()

    /** True if the data starts with a TLS Alert record (ContentType 0x15). */
    val hasAlertRecord: Boolean
        get() = data.size >= 5 && data[0] == 0x15.toByte()

    /**
     * Parsed TLS Alert, or null if the data is not an alert record or too short.
     * Returns the first alert in the byte stream.
     */
    fun parseAlert(): AlertRecord? {
        if (!hasAlertRecord) return null
        if (data.size < 7) return null  // 5-byte header + 2-byte alert body
        val level = data[5].toInt() and 0xFF
        val description = data[6].toInt() and 0xFF
        return AlertRecord(level, description)
    }

    /**
     * Parse the ServerHello from the byte stream, or return null.
     *
     * Searches forward through TLS records for a Handshake record containing
     * a ServerHello message (HandshakeType 0x02).
     */
    fun parseServerHello(): ServerHelloInfo? {
        var pos = 0
        while (pos + 5 <= data.size) {
            val contentType = data[pos].toInt() and 0xFF
            val recMajor   = data[pos + 1].toInt() and 0xFF
            val recMinor   = data[pos + 2].toInt() and 0xFF
            val recLen     = readUint16(pos + 3)
            pos += 5

            if (pos + recLen > data.size) break  // truncated record
            if (contentType != 0x16) {           // not a Handshake record
                pos += recLen
                continue
            }

            // Walk handshake messages within this record
            var hPos = pos
            val recEnd = pos + recLen
            while (hPos + 4 <= recEnd) {
                val msgType = data[hPos].toInt() and 0xFF
                val msgLen  = readUint24(hPos + 1)
                hPos += 4

                if (hPos + msgLen > recEnd) break    // truncated handshake msg

                if (msgType == 0x02) {               // ServerHello
                    return parseServerHelloBody(hPos, msgLen)
                }
                hPos += msgLen
            }
            pos += recLen
        }
        return null
    }

    /**
     * Parse a DHE ServerKeyExchange from the byte stream and return [DhParams].
     *
     * Looks for HandshakeType 0x0C (ServerKeyExchange) in the record stream.
     * Interprets the body as a ServerDHParams structure (RFC 5246 §7.4.3):
     *   dh_p (2-byte len + bytes), dh_g (2-byte len + bytes), dh_Ys (2-byte len + bytes).
     *
     * Returns null if not found or not a DHE key exchange.
     */
    fun parseDhServerKeyExchange(): DhParams? {
        var pos = 0
        while (pos + 5 <= data.size) {
            val contentType = data[pos].toInt() and 0xFF
            val recLen     = readUint16(pos + 3)
            pos += 5

            if (pos + recLen > data.size) break
            if (contentType != 0x16) {
                pos += recLen
                continue
            }

            var hPos = pos
            val recEnd = pos + recLen
            while (hPos + 4 <= recEnd) {
                val msgType = data[hPos].toInt() and 0xFF
                val msgLen  = readUint24(hPos + 1)
                hPos += 4

                if (hPos + msgLen > recEnd) break

                if (msgType == 0x0C) {    // ServerKeyExchange
                    return parseDhParams(hPos, msgLen)
                }
                hPos += msgLen
            }
            pos += recLen
        }
        return null
    }

    // -------------------------------------------------------------------------
    // Internal parsers
    // -------------------------------------------------------------------------

    private fun parseServerHelloBody(start: Int, len: Int): ServerHelloInfo? {
        if (len < 38) return null   // version(2) + random(32) + sessionIdLen(1) + cs(2) + comp(1)
        var p = start

        val major  = data[p].toInt() and 0xFF
        val minor  = data[p + 1].toInt() and 0xFF
        p += 2 + 32  // skip version + Random

        val sessionIdLen = data[p].toInt() and 0xFF
        p += 1 + sessionIdLen

        if (p + 3 > start + len) return null
        val cipherSuite = readUint16(p)
        p += 2
        val compressionMethod = data[p].toInt() and 0xFF
        p += 1

        // Extensions (optional)
        val extensionTypes = mutableSetOf<Int>()
        if (p + 2 <= start + len) {
            val extTotalLen = readUint16(p)
            p += 2
            var ep = p
            val extEnd = p + extTotalLen
            while (ep + 4 <= extEnd) {
                val extType = readUint16(ep)
                val extLen  = readUint16(ep + 2)
                extensionTypes.add(extType)
                ep += 4 + extLen
            }
        }

        // Map version bytes to TlsProtocol
        val protocol = TlsProtocol.entries.firstOrNull { it.major == major && it.minor == minor }

        return ServerHelloInfo(
            protocol = protocol,
            majorByte = major,
            minorByte = minor,
            cipherSuite = cipherSuite,
            compressionMethod = compressionMethod,
            extensionTypes = extensionTypes,
            heartbeatOffered = 0x000F in extensionTypes,
        )
    }

    private fun parseDhParams(start: Int, len: Int): DhParams? {
        var p = start
        val end = start + len

        // dh_p
        if (p + 2 > end) return null
        val pLen = readUint16(p);  p += 2
        if (p + pLen > end) return null
        val pBytes = data.copyOfRange(p, p + pLen);  p += pLen

        // dh_g
        if (p + 2 > end) return null
        val gLen = readUint16(p);  p += 2
        if (p + gLen > end) return null
        // g bytes not needed for weakness checks but advance past them
        p += gLen

        // Compute SHA-256 of the raw prime bytes (for catalog lookup)
        val sha256 = MessageDigest.getInstance("SHA-256").digest(pBytes)
        val sha256Hex = sha256.joinToString("") { "%02x".format(it) }

        val primeBigInt = BigInteger(1, pBytes)   // positive interpretation

        return DhParams(
            sizeBits = primeBigInt.bitLength(),
            sha256Hex = sha256Hex,
            primeHex = pBytes.joinToString("") { "%02x".format(it) },
        )
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private fun readUint16(pos: Int): Int =
        ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)

    private fun readUint24(pos: Int): Int =
        ((data[pos].toInt() and 0xFF) shl 16) or
        ((data[pos + 1].toInt() and 0xFF) shl 8) or
        (data[pos + 2].toInt() and 0xFF)

    // -------------------------------------------------------------------------
    // Result types
    // -------------------------------------------------------------------------

    /** A TLS Alert record (RFC 5246 §7.2). */
    data class AlertRecord(
        /** AlertLevel: 1 = warning, 2 = fatal. */
        val level: Int,
        /** AlertDescription code (e.g. 40 = handshake_failure, 70 = protocol_version). */
        val description: Int,
    ) {
        val isFatal: Boolean get() = level == 2
        val isFatalHandshakeFailure: Boolean get() = isFatal && description == 40
    }

    /** Parsed ServerHello fields. */
    data class ServerHelloInfo(
        /** Matched TlsProtocol if the version bytes are recognized, null otherwise. */
        val protocol: TlsProtocol?,
        /** Raw major byte from the ServerHello ProtocolVersion field. */
        val majorByte: Int,
        /** Raw minor byte from the ServerHello ProtocolVersion field. */
        val minorByte: Int,
        /** IANA cipher suite code selected by the server. */
        val cipherSuite: Int,
        /** Compression method (0 = no compression). */
        val compressionMethod: Int,
        /** All extension type codes present in the server's ServerHello. */
        val extensionTypes: Set<Int>,
        /** True if the server included the Heartbeat extension (0x000F, RFC 6520). */
        val heartbeatOffered: Boolean,
    )

    /**
     * Diffie-Hellman prime parameters extracted from a DHE ServerKeyExchange.
     *
     * Used by Logjam and weak-DH probes.
     */
    data class DhParams(
        /** Bit length of the DH prime p. */
        val sizeBits: Int,
        /** SHA-256 hex digest of the raw big-endian prime bytes. Used for catalog lookup. */
        val sha256Hex: String,
        /** Full hex encoding of the prime bytes (for display in findings). */
        val primeHex: String,
    )

}
