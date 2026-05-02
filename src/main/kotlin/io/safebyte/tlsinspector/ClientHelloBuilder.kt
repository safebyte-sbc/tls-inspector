package io.safebyte.tlsinspector

import java.io.ByteArrayOutputStream
import java.security.SecureRandom

/**
 * Builds raw TLS ClientHello records as byte arrays.
 *
 * Used by raw-socket probes (HeartbleedProbe, DROWN, etc.) that need to send a
 * custom ClientHello — something BCTLS's high-level API does not allow.
 *
 * The generated record follows RFC 5246 §7.4.1.2 (ClientHello) wrapped in a
 * TLS Record Layer header (RFC 5246 §6.2.1).
 *
 * Usage:
 * ```kotlin
 * val hello = ClientHelloBuilder.build(
 *     version = TlsProtocol.TLS_1_2,
 *     sni = "example.com",
 *     cipherSuites = listOf(0xC02F, 0xC030, 0x002F),
 *     includeHeartbeat = true,
 * )
 * val outcome = TlsConnector(ctx).probeRawAfterHello(hello, ByteArray(0))
 * ```
 */
object ClientHelloBuilder {

    private val rng = SecureRandom()

    /**
     * Build a complete TLS ClientHello record.
     *
     * @param version        The TLS version to advertise in the ClientHello header.
     *                       Must NOT be [TlsProtocol.SSL_2_0].
     * @param sni            Server Name Indication hostname. Pass empty string to omit SNI.
     * @param cipherSuites   IANA cipher suite codes (16-bit, stored as Int).
     *                       Defaults to a broad modern list.
     * @param compressionMethods  Compression method bytes. Defaults to [0x00] (no compression).
     * @param includeHeartbeat    If true, appends a Heartbeat extension (RFC 6520) offering
     *                            peer_allowed_to_send=1. Required for Heartbleed probes.
     * @param extraExtensions     Additional [TlsExtension] values appended after built-ins.
     * @return Full TLS record layer bytes (5-byte header + handshake message).
     */
    fun build(
        version: TlsProtocol,
        sni: String,
        cipherSuites: List<Int> = DEFAULT_CIPHER_SUITES,
        compressionMethods: ByteArray = byteArrayOf(0x00),
        includeHeartbeat: Boolean = false,
        includeFallbackScsv: Boolean = false,
        extraExtensions: List<TlsExtension> = emptyList(),
    ): ByteArray {
        require(version != TlsProtocol.SSL_2_0) {
            "SSL 2.0 ClientHello format differs from TLS — use a dedicated SSLv2 builder"
        }

        // --- ClientHello body ---
        val hello = ByteArrayOutputStream()

        // ProtocolVersion client_version (2 bytes)
        hello.write(version.major)
        hello.write(version.minor)

        // Random: 4-byte GMT Unix time + 28 random bytes
        val random = ByteArray(28).also { rng.nextBytes(it) }
        val unixTime = (System.currentTimeMillis() / 1000L).toInt()
        hello.write((unixTime ushr 24) and 0xFF)
        hello.write((unixTime ushr 16) and 0xFF)
        hello.write((unixTime ushr  8) and 0xFF)
        hello.write( unixTime          and 0xFF)
        hello.write(random)

        // Session ID: empty (1-byte length + 0 bytes)
        hello.write(0x00)

        // CipherSuites: 2-byte count (number of bytes = count * 2) + suite codes
        // TLS_FALLBACK_SCSV (RFC 7507, code 0x5600) is appended as the last entry
        // when includeFallbackScsv=true to signal a protocol-downgrade connection.
        val effectiveCiphers = if (includeFallbackScsv) cipherSuites + listOf(0x5600) else cipherSuites
        val cipherBytes = effectiveCiphers.size * 2
        hello.write((cipherBytes ushr 8) and 0xFF)
        hello.write( cipherBytes         and 0xFF)
        for (suite in effectiveCiphers) {
            hello.write((suite ushr 8) and 0xFF)
            hello.write( suite         and 0xFF)
        }

        // CompressionMethods: 1-byte length + methods
        hello.write(compressionMethods.size)
        hello.write(compressionMethods)

        // --- Extensions ---
        val extBuf = ByteArrayOutputStream()

        // SNI extension (type 0x0000) — only if sni is non-empty
        if (sni.isNotEmpty()) {
            extBuf.writeExtension(TlsExtension.serverNameIndication(sni))
        }

        // Signature Algorithms extension (type 0x000D) — required for TLS 1.2+
        if (version == TlsProtocol.TLS_1_2 || version == TlsProtocol.TLS_1_3) {
            extBuf.writeExtension(TlsExtension.signatureAlgorithms())
        }

        // Supported Groups (Named Curves) — type 0x000A
        extBuf.writeExtension(TlsExtension.supportedGroups())

        // EC Point Formats — type 0x000B
        extBuf.writeExtension(TlsExtension.ecPointFormats())

        // Heartbeat extension — type 0x000F (RFC 6520)
        if (includeHeartbeat) {
            extBuf.writeExtension(TlsExtension.heartbeat())
        }

        // Any caller-supplied extra extensions
        for (ext in extraExtensions) {
            extBuf.writeExtension(ext)
        }

        // Write extensions block: 2-byte total length + extension bytes
        val extBytes = extBuf.toByteArray()
        if (extBytes.isNotEmpty()) {
            hello.write((extBytes.size ushr 8) and 0xFF)
            hello.write( extBytes.size         and 0xFF)
            hello.write(extBytes)
        }

        // --- Handshake message: type ClientHello (0x01) + 3-byte length ---
        val helloBytes = hello.toByteArray()
        val handshake = ByteArrayOutputStream()
        handshake.write(0x01)                                         // HandshakeType.client_hello
        handshake.write((helloBytes.size ushr 16) and 0xFF)
        handshake.write((helloBytes.size ushr  8) and 0xFF)
        handshake.write( helloBytes.size           and 0xFF)
        handshake.write(helloBytes)

        // --- TLS Record Layer: ContentType 0x16 (handshake) + version + 2-byte length ---
        val hsBytes = handshake.toByteArray()
        val record = ByteArrayOutputStream()
        record.write(0x16)                                            // ContentType.handshake
        record.write(version.major)
        record.write(version.minor)
        record.write((hsBytes.size ushr 8) and 0xFF)
        record.write( hsBytes.size         and 0xFF)
        record.write(hsBytes)

        return record.toByteArray()
    }

    /** Write a [TlsExtension] into this stream: 2-byte type + 2-byte data length + data. */
    private fun ByteArrayOutputStream.writeExtension(ext: TlsExtension) {
        write((ext.type ushr 8) and 0xFF)
        write( ext.type         and 0xFF)
        write((ext.data.size ushr 8) and 0xFF)
        write( ext.data.size         and 0xFF)
        write(ext.data)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // MS C — helpers for ROBOT and Raccoon (ported from standalone)
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * TLS 1.2 ClientHello with only TLS_RSA_* cipher suites (no DHE, no ECDHE).
     * Forces RSA key-exchange path — required for ROBOT oracle probing.
     */
    fun buildRsaOnlyClientHello(sni: String): ByteArray = build(
        version = TlsProtocol.TLS_1_2,
        sni = sni,
        cipherSuites = listOf(0x002F, 0x0035, 0x003C, 0x003D, 0x009C, 0x009D),
    )

    /**
     * TLS 1.2 ClientHello with only TLS_DHE_RSA_* cipher suites.
     * Forces DHE key-exchange path — required for Raccoon Ys-reuse detection.
     */
    fun buildDheRsaOnlyClientHello(sni: String): ByteArray = build(
        version = TlsProtocol.TLS_1_2,
        sni = sni,
        cipherSuites = listOf(0x0033, 0x0039, 0x0067, 0x006B, 0x009E, 0x009F),
    )

    /**
     * Build a raw TLS 1.2 ClientKeyExchange record wrapping [encryptedPms].
     * Wire format: TLS record (type 0x16, version 0x0303) + handshake header
     * (type 0x10 ClientKeyExchange) + 2-byte EncryptedPreMasterSecret length + encryptedPms.
     */
    fun buildClientKeyExchangeRsa(encryptedPms: ByteArray): ByteArray {
        // Handshake body: 2-byte length prefix + encryptedPms
        val ckeBody = byteArrayOf(
            ((encryptedPms.size shr 8) and 0xFF).toByte(),
            (encryptedPms.size and 0xFF).toByte()
        ) + encryptedPms

        // Handshake header: type 0x10 + 3-byte body length
        val handshake = byteArrayOf(
            0x10,
            ((ckeBody.size shr 16) and 0xFF).toByte(),
            ((ckeBody.size shr  8) and 0xFF).toByte(),
            ( ckeBody.size and 0xFF).toByte()
        ) + ckeBody

        // TLS record: type 0x16, version TLS 1.2 (0x03 0x03)
        return byteArrayOf(
            0x16, 0x03, 0x03,
            ((handshake.size shr 8) and 0xFF).toByte(),
            (handshake.size and 0xFF).toByte()
        ) + handshake
    }

    // DHE cipher codes for Logjam / Raccoon probes
    val DHE_CIPHER_CODES: List<Int> = listOf(
        0x0033, // TLS_DHE_RSA_WITH_AES_128_CBC_SHA
        0x0039, // TLS_DHE_RSA_WITH_AES_256_CBC_SHA
        0x0067, // TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
        0x006B, // TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
        0x009E, // TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
        0x009F, // TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
        0x00A2, // TLS_DHE_DSS_WITH_AES_128_GCM_SHA256
        0x00A3, // TLS_DHE_DSS_WITH_AES_256_GCM_SHA384
        0x0032, // TLS_DHE_DSS_WITH_AES_128_CBC_SHA
        0x0038, // TLS_DHE_DSS_WITH_AES_256_CBC_SHA
        0x0040, // TLS_DHE_DSS_WITH_AES_128_CBC_SHA256
        0x006A, // TLS_DHE_DSS_WITH_AES_256_CBC_SHA256
    )

    // Export RSA cipher codes for FREAK probe
    val EXPORT_RSA_CIPHER_CODES: List<Int> = listOf(
        0x0003, // TLS_RSA_EXPORT_WITH_RC4_40_MD5
        0x0006, // TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
        0x0008, // TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
        0x000B, // TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA
        0x000E, // TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
    )

    // Export DHE cipher codes for Logjam Export probe
    val EXPORT_DHE_CIPHER_CODES: List<Int> = listOf(
        0x0011, // TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
        0x000E, // TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
        0x0014, // TLS_DHE_anon_EXPORT_WITH_RC4_40_MD5
        0x0017, // TLS_DHE_anon_EXPORT_WITH_DES40_CBC_SHA
    )

    // 3DES cipher codes for Sweet32 probe
    val TRIPLE_DES_CIPHER_CODES: List<Int> = listOf(
        0x000A, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
        0x000D, // TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA
        0x0010, // TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA
        0x0013, // TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
        0x0016, // TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
        0xC01A, // TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA
        0xC01B, // TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA
        0xC01C, // TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA
    )

    // CBC cipher codes for POODLE / BEAST / Lucky13 probes
    val CBC_CIPHER_CODES: List<Int> = listOf(
        0x002F, // TLS_RSA_WITH_AES_128_CBC_SHA
        0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
        0x003C, // TLS_RSA_WITH_AES_128_CBC_SHA256
        0x003D, // TLS_RSA_WITH_AES_256_CBC_SHA256
        0x0033, // TLS_DHE_RSA_WITH_AES_128_CBC_SHA
        0x0039, // TLS_DHE_RSA_WITH_AES_256_CBC_SHA
        0x0067, // TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
        0x006B, // TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
        0xC013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        0xC014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
        0xC027, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
        0xC028, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
        0x000A, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
    )

    // ─────────────────────────────────────────────────────────────────────────
    // MS E — PQC Hybrid KEM probe helpers
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Build a TLS 1.3 ClientHello that advertises [offeredGroups] in the supported_groups
     * and key_share extensions.
     *
     * When [classicalKeyShareOnly] is true, the key_share extension only includes key-share
     * entries for classical groups (X25519, secp256r1) — this forces the server to respond
     * with a HelloRetryRequest if it wants a PQC group, revealing PQC preference.
     *
     * When [classicalKeyShareOnly] is false, we send an empty key_share list for simplicity
     * (the server will HRR for any group it selects).
     *
     * Ref: RFC 8446 §4.2.8 (key_share), §4.2.7 (supported_groups)
     */
    fun buildPqcClientHello(
        sni: String,
        offeredGroups: IntArray,
        classicalKeyShareOnly: Boolean = true,
    ): ByteArray {
        // TLS 1.3 cipher suites
        val tls13Ciphers = listOf(0x1301, 0x1302, 0x1303)

        // supported_versions extension: TLS 1.3 (0x0304)
        val supportedVersionsExt = run {
            val buf = ByteArrayOutputStream()
            // supported_versions is a list of ProtocolVersion: 1-byte length + 2-byte versions
            buf.write(0x02)  // list length = 2 bytes (one version)
            buf.write(0x03)
            buf.write(0x04)  // TLS 1.3
            TlsExtension(0x002B, buf.toByteArray())
        }

        // supported_groups extension with all offeredGroups
        val supportedGroupsExt = run {
            val buf = ByteArrayOutputStream()
            val listBytes = offeredGroups.size * 2
            buf.write((listBytes ushr 8) and 0xFF)
            buf.write( listBytes         and 0xFF)
            for (g in offeredGroups) {
                buf.write((g ushr 8) and 0xFF)
                buf.write( g         and 0xFF)
            }
            TlsExtension(0x000A, buf.toByteArray())
        }

        // key_share extension
        val keyShareExt = run {
            val entriesBuf = ByteArrayOutputStream()
            if (classicalKeyShareOnly) {
                // Only include key shares for classical groups we're offering
                for (g in offeredGroups) {
                    val keyBytes = when (g) {
                        0x001D -> ByteArray(32).also { rng.nextBytes(it) }  // X25519: 32 random bytes
                        0x0017 -> buildUncompressedPoint(32)                 // secp256r1: 65 bytes
                        0x0018 -> buildUncompressedPoint(48)                 // secp384r1: 97 bytes
                        else -> null  // Skip PQC groups — server must HRR
                    } ?: continue
                    // key_share_entry: group(2) + key_exchange_length(2) + key_exchange_data
                    entriesBuf.write((g ushr 8) and 0xFF)
                    entriesBuf.write( g         and 0xFF)
                    entriesBuf.write((keyBytes.size ushr 8) and 0xFF)
                    entriesBuf.write( keyBytes.size         and 0xFF)
                    entriesBuf.write(keyBytes)
                }
            }
            // key_share: 2-byte client_shares list length + entries
            val entriesBytes = entriesBuf.toByteArray()
            val buf = ByteArrayOutputStream()
            buf.write((entriesBytes.size ushr 8) and 0xFF)
            buf.write( entriesBytes.size         and 0xFF)
            buf.write(entriesBytes)
            TlsExtension(0x0033, buf.toByteArray())
        }

        // Build the ClientHello with extra extensions for TLS 1.3
        return build(
            version = TlsProtocol.TLS_1_2,  // Outer record version = 0x0303 for compat; TLS 1.3 negotiated via supported_versions
            sni = sni,
            cipherSuites = tls13Ciphers,
            extraExtensions = listOf(supportedVersionsExt, supportedGroupsExt, keyShareExt),
        )
    }

    /**
     * Build an uncompressed EC point: 0x04 || X (n bytes) || Y (n bytes).
     * We use random bytes for X and Y — valid form, server won't check for DH correctness
     * during HRR / ServerHello selection.
     */
    private fun buildUncompressedPoint(coordBytes: Int): ByteArray {
        val coordData = ByteArray(coordBytes * 2).also { rng.nextBytes(it) }
        return byteArrayOf(0x04) + coordData
    }

    /** Default broad cipher suite list for raw probes. */
    val DEFAULT_CIPHER_SUITES: List<Int> = listOf(
        0xC02C, 0xC02B, // ECDHE-ECDSA-AES256/128-GCM-SHA384/256
        0xC030, 0xC02F, // ECDHE-RSA-AES256/128-GCM-SHA384/256
        0xC028, 0xC027, // ECDHE-RSA-AES256/128-SHA384/256
        0xC014, 0xC013, // ECDHE-RSA-AES256/128-SHA
        0x009D, 0x009C, // AES256/128-GCM-SHA384/256
        0x003D, 0x003C, // AES256/128-CBC-SHA256
        0x0035, 0x002F, // AES256/128-CBC-SHA
        0x000A, 0x0005, // DES-CBC3-SHA, RC4-SHA
    )
}

/**
 * A raw TLS extension value: 16-bit type identifier and opaque data bytes.
 *
 * Factory methods in the companion object cover all extensions needed by MS B probes.
 */
data class TlsExtension(val type: Int, val data: ByteArray) {

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is TlsExtension) return false
        return type == other.type && data.contentEquals(other.data)
    }

    override fun hashCode(): Int = 31 * type + data.contentHashCode()

    companion object {

        /**
         * SNI extension (type 0x0000, RFC 6066 §3).
         * Encodes a single host_name entry.
         */
        fun serverNameIndication(hostname: String): TlsExtension {
            val nameBytes = hostname.toByteArray(Charsets.US_ASCII)
            val buf = ByteArrayOutputStream()
            // ServerNameList: 2-byte list length
            val listLen = 1 + 2 + nameBytes.size   // NameType(1) + length(2) + name
            buf.write((listLen ushr 8) and 0xFF)
            buf.write( listLen         and 0xFF)
            buf.write(0x00)                          // NameType.host_name
            buf.write((nameBytes.size ushr 8) and 0xFF)
            buf.write( nameBytes.size          and 0xFF)
            buf.write(nameBytes)
            return TlsExtension(0x0000, buf.toByteArray())
        }

        /**
         * Heartbeat extension (type 0x000F, RFC 6520).
         * mode = peer_allowed_to_send (1). Enables Heartbleed probing.
         */
        fun heartbeat(): TlsExtension =
            TlsExtension(0x000F, byteArrayOf(0x01))   // HeartbeatMode.peer_allowed_to_send

        /**
         * Signature Algorithms extension (type 0x000D, RFC 5246 §7.4.1.4.1).
         * Advertises common algorithm pairs expected by TLS 1.2 servers.
         */
        fun signatureAlgorithms(): TlsExtension {
            // Each algorithm pair: 2 bytes (hash algorithm, signature algorithm)
            val pairs = byteArrayOf(
                0x04, 0x01,   // SHA-256 + RSA
                0x05, 0x01,   // SHA-384 + RSA
                0x06, 0x01,   // SHA-512 + RSA
                0x04, 0x03,   // SHA-256 + ECDSA
                0x05, 0x03,   // SHA-384 + ECDSA
                0x02, 0x01,   // SHA-1   + RSA
                0x02, 0x03,   // SHA-1   + ECDSA
            )
            val buf = ByteArrayOutputStream()
            // supported_signature_algs: 2-byte list length (bytes)
            buf.write((pairs.size ushr 8) and 0xFF)
            buf.write( pairs.size         and 0xFF)
            buf.write(pairs)
            return TlsExtension(0x000D, buf.toByteArray())
        }

        /**
         * Supported Groups (Named Curves) extension (type 0x000A, RFC 4492 §5.1.1).
         * Lists ECDH curves advertised by the client.
         */
        fun supportedGroups(): TlsExtension {
            val curves = shortArrayOf(
                0x001D.toShort(),   // x25519
                0x0017.toShort(),   // secp256r1
                0x0018.toShort(),   // secp384r1
                0x0019.toShort(),   // secp521r1
                0x001E.toShort(),   // x448
            )
            val buf = ByteArrayOutputStream()
            val listBytes = curves.size * 2
            buf.write((listBytes ushr 8) and 0xFF)
            buf.write( listBytes         and 0xFF)
            for (c in curves) {
                buf.write((c.toInt() ushr 8) and 0xFF)
                buf.write( c.toInt()          and 0xFF)
            }
            return TlsExtension(0x000A, buf.toByteArray())
        }

        /**
         * EC Point Formats extension (type 0x000B, RFC 4492 §5.1.2).
         * Advertises uncompressed as the only accepted format.
         */
        fun ecPointFormats(): TlsExtension {
            // formats list: 1-byte length + format codes
            val buf = ByteArrayOutputStream()
            buf.write(0x01)   // list length
            buf.write(0x00)   // ECPointFormat.uncompressed
            return TlsExtension(0x000B, buf.toByteArray())
        }
    }
}
