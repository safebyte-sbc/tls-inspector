package io.safebyte.tlsinspector

/**
 * Outcome of a PQC KEM probe attempt.
 * Used by TlsConnector.probePqcSupportedGroups() and PqcKemProbe.
 */
sealed class PqcProbeOutcome {
    /** Server responded with a HelloRetryRequest selecting [selectedGroup]. */
    data class HelloRetryRequest(val selectedGroup: Int) : PqcProbeOutcome()
    /** Server responded with a ServerHello selecting [selectedGroup] in key_share. */
    data class ServerHelloKeyShare(val selectedGroup: Int) : PqcProbeOutcome()
    /** Server sent an alert (e.g. handshake_failure). */
    data class AlertReceived(val description: Int) : PqcProbeOutcome()
    /** Server sent no recognisable response within budget. */
    object NoResponse : PqcProbeOutcome()
    /** I/O or connect error. */
    data class IoError(val reason: String) : PqcProbeOutcome()
}

/**
 * PQC Named Group IANA codes (draft-ietf-tls-ecdhe-mlkem and predecessors).
 *
 * 0x11EC = X25519MLKEM768  (primary, recommended by IETF draft)
 * 0x6399 = X25519Kyber768Draft00  (older Google/Cloudflare draft)
 * 0x2F39 = SecP256r1MLKEM768  (NIST curve variant, draft-06+)
 */
object PqcGroups {
    const val X25519MLKEM768       = 0x11EC
    const val X25519Kyber768Draft  = 0x6399
    const val SecP256r1MLKEM768    = 0x2F39

    /** Classical groups to include in hybrid offers. */
    val CLASSICAL = intArrayOf(
        0x001D, // x25519
        0x0017, // secp256r1
        0x0018, // secp384r1
    )

    /** All PQC group codes we probe for. */
    val ALL_PQC = intArrayOf(X25519MLKEM768, X25519Kyber768Draft, SecP256r1MLKEM768)
}

/**
 * Parse a raw TLS record byte array (as returned by TlsRawSocket.readTlsRecord)
 * and classify it as a PqcProbeOutcome.
 *
 * This handles:
 *   - Alert records (ContentType 0x15) → AlertReceived
 *   - Handshake records containing ServerHello (type 0x02) → HelloRetryRequest or ServerHelloKeyShare
 *   - Anything else → NoResponse
 *
 * RFC 8446 §4.1.3 HRR magic random:
 *   CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C
 */
internal object PqcResponseParser {

    private val HRR_MAGIC = byteArrayOf(
        0xCF.toByte(), 0x21.toByte(), 0xAD.toByte(), 0x74.toByte(),
        0xE5.toByte(), 0x9A.toByte(), 0x61.toByte(), 0x11.toByte(),
        0xBE.toByte(), 0x1D.toByte(), 0x8C.toByte(), 0x02.toByte(),
        0x1E.toByte(), 0x65.toByte(), 0xB8.toByte(), 0x91.toByte(),
        0xC2.toByte(), 0xA2.toByte(), 0x11.toByte(), 0x16.toByte(),
        0x7A.toByte(), 0xBB.toByte(), 0x8C.toByte(), 0x5E.toByte(),
        0x07.toByte(), 0x9E.toByte(), 0x09.toByte(), 0xE2.toByte(),
        0xC8.toByte(), 0xA8.toByte(), 0x33.toByte(), 0x9C.toByte()
    )

    fun parse(bytes: ByteArray): PqcProbeOutcome {
        if (bytes.size < 5) return PqcProbeOutcome.NoResponse

        val recType = bytes[0].toInt() and 0xFF

        // Alert record
        if (recType == 0x15) {
            return if (bytes.size >= 7) PqcProbeOutcome.AlertReceived(bytes[6].toInt() and 0xFF)
            else PqcProbeOutcome.NoResponse
        }

        // Handshake record
        if (recType != 0x16) return PqcProbeOutcome.NoResponse

        val shBody = findServerHelloBody(bytes) ?: return PqcProbeOutcome.NoResponse
        val isHrr = matchesHrrMagic(shBody)
        val selectedGroup = parseKeyShareGroup(shBody, isHrr) ?: return PqcProbeOutcome.NoResponse

        return if (isHrr) PqcProbeOutcome.HelloRetryRequest(selectedGroup)
        else PqcProbeOutcome.ServerHelloKeyShare(selectedGroup)
    }

    /**
     * Walk TLS records and find the body of the first ServerHello (handshake type 0x02).
     * Returns the bytes AFTER the 4-byte handshake header (type + 3-byte length),
     * i.e. version(2) + random(32) + session_id_len(1) + ...
     */
    private fun findServerHelloBody(raw: ByteArray): ByteArray? {
        var recOffset = 0
        while (recOffset + 5 <= raw.size) {
            val recContentType = raw[recOffset].toInt() and 0xFF
            val recLen = ((raw[recOffset + 3].toInt() and 0xFF) shl 8) or
                          (raw[recOffset + 4].toInt() and 0xFF)
            val payloadStart = recOffset + 5
            val payloadEnd = payloadStart + recLen

            if (recContentType == 0x16 && payloadEnd <= raw.size) {
                // Walk handshake messages inside this record
                var hsOffset = payloadStart
                while (hsOffset + 4 <= payloadEnd) {
                    val hsType = raw[hsOffset].toInt() and 0xFF
                    val hsLen = ((raw[hsOffset + 1].toInt() and 0xFF) shl 16) or
                                ((raw[hsOffset + 2].toInt() and 0xFF) shl 8)  or
                                 (raw[hsOffset + 3].toInt() and 0xFF)
                    val bodyStart = hsOffset + 4
                    val bodyEnd = bodyStart + hsLen
                    if (hsType == 0x02 && bodyEnd <= raw.size) {
                        return raw.copyOfRange(bodyStart, bodyEnd)
                    }
                    hsOffset += 4 + hsLen
                }
            }
            recOffset += 5 + recLen
        }
        return null
    }

    /** Check if ServerHello.random (bytes [2..33]) equals the HRR magic constant. */
    private fun matchesHrrMagic(shBody: ByteArray): Boolean {
        if (shBody.size < 2 + 32) return false
        for (i in 0 until 32) {
            if (shBody[2 + i] != HRR_MAGIC[i]) return false
        }
        return true
    }

    /**
     * Parse the key_share extension (type 0x0033) from a ServerHello body.
     *
     * ServerHello body layout:
     *   version(2) + random(32) + session_id_len(1) + session_id(N) +
     *   cipher_suite(2) + compression(1) + extensions_len(2) + extensions(...)
     *
     * In HRR the key_share ext data is just the selected_group(2).
     * In a normal ServerHello it's group(2) + key_exchange_len(2) + key_exchange_data.
     * We only need the group for PQC detection.
     */
    private fun parseKeyShareGroup(shBody: ByteArray, isHrr: Boolean): Int? {
        var pos = 2 + 32  // skip version + random
        if (pos >= shBody.size) return null

        val sessionIdLen = shBody[pos].toInt() and 0xFF
        pos += 1 + sessionIdLen + 2 + 1  // session_id + cipher_suite + compression

        if (pos + 2 > shBody.size) return null
        val extTotalLen = ((shBody[pos].toInt() and 0xFF) shl 8) or
                           (shBody[pos + 1].toInt() and 0xFF)
        pos += 2

        val extEnd = pos + extTotalLen
        while (pos + 4 <= extEnd && pos + 4 <= shBody.size) {
            val extType = ((shBody[pos].toInt() and 0xFF) shl 8) or
                           (shBody[pos + 1].toInt() and 0xFF)
            val extLen = ((shBody[pos + 2].toInt() and 0xFF) shl 8) or
                          (shBody[pos + 3].toInt() and 0xFF)
            pos += 4

            if (extType == 0x0033 && pos + 2 <= shBody.size) {
                // key_share: in HRR it's just a 2-byte selected_group
                val group = ((shBody[pos].toInt() and 0xFF) shl 8) or
                             (shBody[pos + 1].toInt() and 0xFF)
                return group
            }
            pos += extLen
        }
        return null
    }
}
