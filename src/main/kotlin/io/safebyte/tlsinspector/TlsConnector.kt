package io.safebyte.tlsinspector

import org.bouncycastle.tls.AlertDescription
import org.bouncycastle.tls.AlertLevel
import org.bouncycastle.tls.DefaultTlsClient
import org.bouncycastle.tls.ProtocolVersion
import org.bouncycastle.tls.ServerName
import org.bouncycastle.tls.TlsAuthentication
import org.bouncycastle.tls.TlsClientProtocol
import org.bouncycastle.tls.TlsCredentials
import org.bouncycastle.tls.TlsExtensionsUtils
import org.bouncycastle.tls.TlsFatalAlert
import org.bouncycastle.tls.TlsServerCertificate
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.time.Duration
import java.time.Instant
import java.util.Vector

// ─────────────────────────────────────────────────────────────────────────
// Raw-socket helpers — ported from the validated standalone TLS tester.
// These are used by probes that need wire-level control (Heartbleed, CCS,
// POODLE, FREAK, CRIME, Logjam, ROBOT, Raccoon) and cannot go through BCTLS.
// ─────────────────────────────────────────────────────────────────────────

object TlsRawSocket {

    /**
     * Open a raw TCP socket to host:port.
     * Uses the probe budget's handshake timeout for both connect and SO_TIMEOUT.
     */
    fun openSocket(ctx: ProbeContext): java.net.Socket {
        val sock = java.net.Socket()
        val timeoutMs = ctx.budget.handshakeTimeout.toMillis().toInt()
        sock.tcpNoDelay = true
        sock.soTimeout = timeoutMs
        sock.connect(java.net.InetSocketAddress(ctx.host, ctx.port), timeoutMs)
        return sock
    }

    /**
     * Send [data] and read up to [maxRead] bytes with [readTimeoutMs].
     * Returns empty array on timeout (server silent).
     */
    fun sendAndReceive(
        sock: java.net.Socket,
        data: ByteArray,
        maxRead: Int = 16384,
        readTimeoutMs: Int = 3000
    ): ByteArray {
        sock.soTimeout = readTimeoutMs
        sock.getOutputStream().write(data)
        sock.getOutputStream().flush()
        val buf = ByteArray(maxRead)
        return try {
            val n = sock.getInputStream().read(buf)
            if (n <= 0) ByteArray(0) else buf.copyOf(n)
        } catch (e: java.net.SocketTimeoutException) {
            ByteArray(0)
        }
    }

    /**
     * Read a full TLS record (5-byte header + payload) from the socket.
     * Returns null on connection close, timeout, or malformed header.
     */
    fun readTlsRecord(sock: java.net.Socket, timeoutMs: Int = 3000): ByteArray? {
        sock.soTimeout = timeoutMs
        val inp = sock.getInputStream()
        val header = ByteArray(5)
        try {
            var read = 0
            while (read < 5) {
                val n = inp.read(header, read, 5 - read)
                if (n < 0) return null
                read += n
            }
        } catch (e: java.net.SocketTimeoutException) { return null }
          catch (e: java.io.IOException)              { return null }

        val length = ((header[3].toInt() and 0xFF) shl 8) or (header[4].toInt() and 0xFF)
        if (length <= 0 || length > 65536) return null

        val payload = ByteArray(length)
        try {
            var read = 0
            while (read < length) {
                val n = inp.read(payload, read, length - read)
                if (n < 0) return null
                read += n
            }
        } catch (e: java.net.SocketTimeoutException) { return null }
          catch (e: java.io.IOException)              { return null }

        return header + payload
    }

    /**
     * Read all available TLS records until timeout or ServerHelloDone (0x0E).
     * Returns the concatenated raw bytes and a flag indicating if ServerHelloDone was seen.
     */
    fun readUntilServerHelloDone(
        sock: java.net.Socket,
        timeoutMs: Int = 5000
    ): Pair<ByteArray, Boolean> {
        val buf = mutableListOf<Byte>()
        var seenDone = false
        val deadline = System.currentTimeMillis() + timeoutMs

        while (System.currentTimeMillis() < deadline) {
            val remaining = (deadline - System.currentTimeMillis()).toInt().coerceAtLeast(100)
            val record = readTlsRecord(sock, remaining) ?: break
            buf.addAll(record.toList())

            val recordType = record[0].toInt() and 0xFF
            if (recordType == 0x15) break  // Alert — stop
            if (recordType == 0x16) {
                val payload = record.drop(5)
                var pos = 0
                while (pos + 4 <= payload.size) {
                    val msgType = payload[pos].toInt() and 0xFF
                    val msgLen  = ((payload[pos+1].toInt() and 0xFF) shl 16) or
                                  ((payload[pos+2].toInt() and 0xFF) shl 8)  or
                                   (payload[pos+3].toInt() and 0xFF)
                    if (msgType == 0x0E) {  // ServerHelloDone
                        seenDone = true
                        break
                    }
                    pos += 4 + msgLen
                }
                if (seenDone) break
            }
        }

        return buf.toByteArray() to seenDone
    }

    /**
     * Find the first TLS record of the given content type in raw bytes.
     * Returns the payload bytes (excluding 5-byte header), or null if not found.
     */
    fun findRecord(raw: ByteArray, type: Int): ByteArray? {
        var offset = 0
        while (offset + 5 <= raw.size) {
            val rt = raw[offset].toInt() and 0xFF
            val length = ((raw[offset+3].toInt() and 0xFF) shl 8) or (raw[offset+4].toInt() and 0xFF)
            if (rt == type) {
                val end = (offset + 5 + length).coerceAtMost(raw.size)
                return raw.copyOfRange(offset + 5, end)
            }
            if (length < 0) break
            offset += 5 + length
        }
        return null
    }

    /** Parse the record type byte at [offset] in raw bytes. Returns -1 if too short. */
    fun recordType(raw: ByteArray, offset: Int = 0): Int =
        if (raw.size > offset) raw[offset].toInt() and 0xFF else -1
}

/**
 * Low-level TLS handshake controller. Uses BCTLS instead of JSSE because:
 *   - JSSE doesn't allow ClientHello manipulation (cipher enumeration, ROBOT probe, etc.)
 *   - JSSE doesn't expose all alert types and TCP-level errors uniformly
 *   - BCTLS supports TLS 1.0 / 1.1 even when the JDK has them disabled
 *
 * KNOWN BCTLS LIMITATIONS — when adding probes for legacy protocols:
 *
 *   1. SSLv2 — completely unsupported (no ClientHello format support).
 *      Detected via raw socket — see ProtocolEnumerationProbe.probeSSLv2().
 *
 *   2. SSLv3 — disabled at the BCTLS 1.79 engine level. Requesting
 *      ProtocolVersion.SSLv3 via DefaultTlsClient.getProtocolVersions() causes
 *      the handshake to fail silently before any bytes are sent (the engine
 *      refuses to compose an SSLv3 ClientHello). This means BCTLS WILL report
 *      SSLv3 as NOT_OFFERED even when the server accepts SSLv3.
 *      Workaround: bypass BCTLS — build a raw SSLv3 ClientHello via
 *      ClientHelloBuilder, send via probeRawAfterHello(), inspect the response
 *      record header for type 0x16 + version 0x0300. See
 *      ProtocolEnumerationProbe.probeSSLv3() for the canonical pattern.
 *
 *   3. EXPORT cipher suites and weak crypto (RC4_40, DES_40, RC2_40, etc.)
 *      may be silently filtered out of the offered cipher list at the engine
 *      level even when present in HandshakeParams.cipherSuites. If a probe
 *      depends on exact cipher offering (FREAK, Logjam Export), prefer the
 *      raw ClientHelloBuilder path over BCTLS attempt() for guaranteed wire-
 *      level control.
 *
 *   4. TLS compression negotiation (CRIME) — BCTLS does not advertise DEFLATE
 *      in client compression_methods even if requested. Use ClientHelloBuilder
 *      with compressionMethods = byteArrayOf(0x01, 0x00) for CRIME-style probes.
 *
 *   5. Heartbeat extension exploit (Heartbleed CVE-2014-0160) — BCTLS does not
 *      expose post-handshake raw record send/recv needed to build the malformed
 *      heartbeat record. The current MS A HeartbleedProbe is a stub
 *      (NOT_VULNERABLE for any successful handshake). True exploit requires a
 *      custom TlsClientProtocol subclass, queued for MS C.
 *
 * General rule: any probe that depends on exact wire-level control over the
 * ClientHello (legacy protocols, weak ciphers, custom extensions) MUST use
 * ClientHelloBuilder + probeRawAfterHello(), not the high-level BCTLS attempt().
 */
class TlsConnector(private val ctx: ProbeContext) {

    /**
     * Attempt a single handshake with the given parameters.
     * Returns HandshakeResult.Success if the handshake completes, or one of the
     * specialized failure variants otherwise.
     *
     * IMPORTANT: This method NEVER throws. All exceptions are caught and translated.
     */
    fun attempt(params: HandshakeParams): HandshakeResult {
        val t0 = Instant.now()
        var socket: Socket? = null
        var protocol: TlsClientProtocol? = null
        try {
            socket = Socket()
            socket.tcpNoDelay = true
            socket.soTimeout = ctx.budget.handshakeTimeout.toMillis().toInt()
            socket.connect(
                InetSocketAddress(ctx.host, ctx.port),
                ctx.budget.handshakeTimeout.toMillis().toInt()
            )

            val client = InspectorTlsClient(params)
            protocol = TlsClientProtocol(socket.getInputStream(), socket.getOutputStream())

            try {
                protocol.connect(client)
            } catch (e: TlsFatalAlert) {
                val alertDesc = e.alertDescription
                return HandshakeResult.AlertReceived(
                    elapsed = Duration.between(t0, Instant.now()),
                    alertLevel = AlertLevel.fatal,
                    alertDescription = alertDesc,
                    alertName = AlertDescription.getText(alertDesc),
                    serverHelloProtocol = client.serverNegotiatedVersion,
                    cause = e.message ?: e.javaClass.simpleName
                )
            } catch (e: IOException) {
                val msg = e.message ?: e.javaClass.simpleName
                return when {
                    msg.contains("Connection reset", ignoreCase = true)
                        -> HandshakeResult.ConnectionReset(Duration.between(t0, Instant.now()), msg)
                    msg.contains("timed out", ignoreCase = true)
                        -> HandshakeResult.Timeout(Duration.between(t0, Instant.now()))
                    msg.contains("end of stream", ignoreCase = true) ||
                    msg.contains("EOF", ignoreCase = true)
                        -> HandshakeResult.UnexpectedEof(Duration.between(t0, Instant.now()), msg)
                    else -> HandshakeResult.IoError(Duration.between(t0, Instant.now()), msg)
                }
            }

            // Handshake complete.
            return HandshakeResult.Success(
                elapsed = Duration.between(t0, Instant.now()),
                negotiatedProtocol = client.serverNegotiatedVersion ?: ProtocolVersion.TLSv12,
                negotiatedCipherSuite = client.negotiatedCipherSuiteInt,
                negotiatedCipherSuiteName = TlsConfig.getCipherSuiteName(client.negotiatedCipherSuiteInt),
                serverCertificateChain = client.serverCertificateChainDerEncoded,
                serverExtensions = client.serverExtensionTypes,
                serverSupportedGroups = client.serverNamedGroups
            )
        } catch (e: Exception) {
            return HandshakeResult.IoError(Duration.between(t0, Instant.now()), e.message ?: e.javaClass.simpleName)
        } finally {
            try { protocol?.close() } catch (_: Exception) { }
            try { socket?.close() } catch (_: Exception) { }
        }
    }

    /**
     * Convenience wrapper: attempt a handshake using a [TlsProtocol] value rather than
     * a raw [org.bouncycastle.tls.ProtocolVersion].
     *
     * @return [HandshakeResult.IoError] with message "unsupported protocol …" if [proto]
     *         has no BouncyCastle equivalent (i.e. SSL_2_0).
     */
    fun probeHandshake(proto: TlsProtocol, ciphers: IntArray): HandshakeResult {
        val bcVersion = bcProtocolVersion(proto)
            ?: return HandshakeResult.IoError(java.time.Duration.ZERO, "unsupported protocol $proto")
        return attempt(HandshakeParams.forVersion(bcVersion, ctx.sni, ciphers))
    }

    private fun bcProtocolVersion(p: TlsProtocol): ProtocolVersion? = when (p) {
        TlsProtocol.SSL_3_0 -> ProtocolVersion.SSLv3
        TlsProtocol.TLS_1_0 -> ProtocolVersion.TLSv10
        TlsProtocol.TLS_1_1 -> ProtocolVersion.TLSv11
        TlsProtocol.TLS_1_2 -> ProtocolVersion.TLSv12
        TlsProtocol.TLS_1_3 -> ProtocolVersion.TLSv13
        else -> null
    }

    /**
     * Open a raw TCP socket, send [clientHelloBytes], read the server's response
     * (with a quiet-gap timeout), optionally send [payloadAfterHandshake] and read
     * a second response chunk.
     *
     * This bypasses BCTLS entirely and gives raw byte access to the server's
     * handshake response — required for probes that need post-handshake record
     * manipulation (Heartbleed overflow record, DROWN SSLv2 export key exchange).
     *
     * @return [RawProbeOutcome.Ok] with both byte arrays on success, or
     *         [RawProbeOutcome.Error] on any I/O or connect failure.
     */
    fun probeRawAfterHello(clientHelloBytes: ByteArray, payloadAfterHandshake: ByteArray): RawProbeOutcome {
        val socket = java.net.Socket()
        return try {
            socket.tcpNoDelay = true
            socket.soTimeout = ctx.budget.handshakeTimeout.toMillis().toInt()
            socket.connect(
                java.net.InetSocketAddress(ctx.host, ctx.port),
                ctx.budget.handshakeTimeout.toMillis().toInt()
            )
            val out = socket.getOutputStream()
            val inp = socket.getInputStream()
            out.write(clientHelloBytes)
            out.flush()

            val handshakeBytes = readUntilQuiet(inp, totalDeadlineMs = 3000, quietGapMs = 600)

            val afterBytes = if (payloadAfterHandshake.isNotEmpty()) {
                try {
                    out.write(payloadAfterHandshake)
                    out.flush()
                    readUntilQuiet(inp, totalDeadlineMs = 3000, quietGapMs = 600)
                } catch (_: Exception) {
                    ByteArray(0)
                }
            } else ByteArray(0)

            RawProbeOutcome.Ok(handshakeBytes, afterBytes)
        } catch (e: java.net.ConnectException) {
            RawProbeOutcome.Error("connect failed: ${e.message}")
        } catch (e: java.net.SocketTimeoutException) {
            RawProbeOutcome.Error("timeout")
        } catch (e: Exception) {
            RawProbeOutcome.Error("io error: ${e.message ?: e.javaClass.simpleName}")
        } finally {
            try { socket.close() } catch (_: Exception) {}
        }
    }

    /**
     * Read bytes from a stream until either:
     *  - [totalDeadlineMs] elapses since first call, OR
     *  - [quietGapMs] elapses with no new bytes received after at least one byte arrived.
     *
     * Always returns a ByteArray (empty if nothing arrived within deadline).
     */
    private fun readUntilQuiet(
        inp: java.io.InputStream,
        totalDeadlineMs: Long,
        quietGapMs: Long,
    ): ByteArray {
        val buf = java.io.ByteArrayOutputStream()
        val deadline = System.currentTimeMillis() + totalDeadlineMs
        var lastRead = System.currentTimeMillis()
        val tmp = ByteArray(4096)
        while (System.currentTimeMillis() < deadline) {
            val available = try { inp.available() } catch (_: Exception) { 0 }
            if (available > 0) {
                val n = try { inp.read(tmp, 0, minOf(available, tmp.size)) } catch (_: Exception) { -1 }
                if (n <= 0) break
                buf.write(tmp, 0, n)
                lastRead = System.currentTimeMillis()
            } else {
                if (buf.size() > 0 && System.currentTimeMillis() - lastRead > quietGapMs) break
                try { Thread.sleep(50) } catch (_: InterruptedException) { break }
            }
        }
        return buf.toByteArray()
    }

    // ─────────────────────────────────────────────────────────────────────────
    // MS E — PQC Hybrid KEM probe
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Send a TLS 1.3 ClientHello advertising [offeredGroups] and observe the server's
     * response to detect PQC KEM support (draft-ietf-tls-ecdhe-mlkem).
     *
     * @param offeredGroups  Named group codes to advertise (PQC and/or classical).
     * @param classicalKeyShareOnly  If true, only send key_share entries for classical groups,
     *        forcing a HelloRetryRequest if the server wants a PQC group.
     * @return [PqcProbeOutcome] indicating what the server selected (or why it failed).
     */
    fun probePqcSupportedGroups(
        offeredGroups: IntArray,
        classicalKeyShareOnly: Boolean = true,
    ): PqcProbeOutcome {
        val socket = java.net.Socket()
        return try {
            socket.tcpNoDelay = true
            val timeoutMs = ctx.budget.handshakeTimeout.toMillis().toInt()
            socket.connect(java.net.InetSocketAddress(ctx.host, ctx.port), timeoutMs)
            socket.soTimeout = timeoutMs

            val out = socket.getOutputStream()
            val clientHello = ClientHelloBuilder.buildPqcClientHello(
                ctx.sni, offeredGroups, classicalKeyShareOnly
            )
            out.write(clientHello)
            out.flush()

            // Read the first TLS record — ServerHello or Alert
            val response = TlsRawSocket.readTlsRecord(socket, timeoutMs)
                ?: return PqcProbeOutcome.NoResponse

            PqcResponseParser.parse(response)
        } catch (e: java.net.ConnectException) {
            PqcProbeOutcome.IoError("connect failed: ${e.message}")
        } catch (e: java.net.SocketTimeoutException) {
            PqcProbeOutcome.IoError("timeout")
        } catch (e: Exception) {
            PqcProbeOutcome.IoError(e.message ?: e.javaClass.simpleName)
        } finally {
            try { socket.close() } catch (_: Exception) {}
        }
    }

    /**
     * Inner client class — exposes negotiated state after handshake.
     */
    private inner class InspectorTlsClient(
        private val params: HandshakeParams
    ) : DefaultTlsClient(BcTlsCrypto(SecureRandom())) {

        var serverNegotiatedVersion: ProtocolVersion? = null
            private set
        var negotiatedCipherSuiteInt: Int = -1
            private set
        var serverCertificateChainDerEncoded: List<ByteArray> = emptyList()
            private set
        var serverExtensionTypes: Set<Int> = emptySet()
            private set
        var serverNamedGroups: List<Int> = emptyList()
            private set

        override fun getProtocolVersions(): Array<ProtocolVersion> = params.versions
        override fun getCipherSuites(): IntArray = params.cipherSuites

        @Suppress("UNCHECKED_CAST", "RAW_USE_OF_PARAMETERIZED_TYPE")
        override fun getClientExtensions(): java.util.Hashtable<*, *> {
            val ext: java.util.Hashtable<Any, Any> =
                (super.getClientExtensions() as? java.util.Hashtable<Any, Any>)
                    ?: java.util.Hashtable<Any, Any>()
            if (params.sendSni) {
                val sniVector = Vector<ServerName>()
                sniVector.add(ServerName(0.toShort(), params.sni.toByteArray(StandardCharsets.US_ASCII)))
                TlsExtensionsUtils.addServerNameExtensionClient(ext, sniVector)
            }
            return ext
        }

        override fun notifyServerVersion(serverVersion: ProtocolVersion) {
            super.notifyServerVersion(serverVersion)
            serverNegotiatedVersion = serverVersion
        }

        override fun notifySelectedCipherSuite(selectedCipherSuite: Int) {
            super.notifySelectedCipherSuite(selectedCipherSuite)
            negotiatedCipherSuiteInt = selectedCipherSuite
        }

        override fun getAuthentication(): TlsAuthentication {
            return object : TlsAuthentication {
                override fun notifyServerCertificate(serverCertificate: TlsServerCertificate) {
                    val chain = serverCertificate.certificate.getCertificateList()
                    serverCertificateChainDerEncoded = chain.map { it.encoded }
                }
                override fun getClientCredentials(certificateRequest: org.bouncycastle.tls.CertificateRequest?): TlsCredentials? = null
            }
        }
    }
}

/**
 * Parameters for one handshake attempt.
 */
data class HandshakeParams(
    val versions: Array<ProtocolVersion>,
    val cipherSuites: IntArray,
    val sni: String,
    val sendSni: Boolean = true
) {
    companion object {
        /** Default modern probe: TLS 1.2 + 1.3, modern cipher list. */
        fun modern(sni: String): HandshakeParams = HandshakeParams(
            versions = arrayOf(ProtocolVersion.TLSv13, ProtocolVersion.TLSv12),
            cipherSuites = TlsConfig.DEFAULT_CIPHER_SUITES_MODERN,
            sni = sni
        )

        /** Single-version probe: try only one TLS version, broad cipher list. */
        fun forVersion(version: ProtocolVersion, sni: String, ciphers: IntArray = TlsConfig.ALL_CIPHER_SUITES): HandshakeParams =
            HandshakeParams(versions = arrayOf(version), cipherSuites = ciphers, sni = sni)

        /** Single-cipher probe: one version + one cipher — for cipher enumeration. */
        fun forCipher(version: ProtocolVersion, cipher: Int, sni: String): HandshakeParams =
            HandshakeParams(versions = arrayOf(version), cipherSuites = intArrayOf(cipher), sni = sni)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is HandshakeParams) return false
        return versions.contentEquals(other.versions) &&
            cipherSuites.contentEquals(other.cipherSuites) &&
            sni == other.sni &&
            sendSni == other.sendSni
    }

    override fun hashCode(): Int {
        var result = versions.contentHashCode()
        result = 31 * result + cipherSuites.contentHashCode()
        result = 31 * result + sni.hashCode()
        result = 31 * result + sendSni.hashCode()
        return result
    }
}

/**
 * Result of a handshake attempt — sealed hierarchy makes pattern matching exhaustive.
 */
sealed class HandshakeResult {
    abstract val elapsed: Duration

    data class Success(
        override val elapsed: Duration,
        val negotiatedProtocol: ProtocolVersion,
        val negotiatedCipherSuite: Int,
        val negotiatedCipherSuiteName: String,
        val serverCertificateChain: List<ByteArray>,           // DER-encoded, leaf first
        val serverExtensions: Set<Int>,
        val serverSupportedGroups: List<Int>
    ) : HandshakeResult()

    data class AlertReceived(
        override val elapsed: Duration,
        val alertLevel: Short,
        val alertDescription: Short,
        val alertName: String,
        val serverHelloProtocol: ProtocolVersion?,
        val cause: String
    ) : HandshakeResult()

    data class ConnectionReset(override val elapsed: Duration, val cause: String) : HandshakeResult()
    data class Timeout(override val elapsed: Duration) : HandshakeResult()
    data class UnexpectedEof(override val elapsed: Duration, val cause: String) : HandshakeResult()
    data class IoError(override val elapsed: Duration, val cause: String) : HandshakeResult()

    /** Canonicalized string representation — used by ROBOT-style oracle comparison in MS C. */
    fun canonicalSignature(): String = when (this) {
        is Success -> "OK:${negotiatedProtocol}/${negotiatedCipherSuiteName}"
        is AlertReceived -> "ALERT:${alertLevel}_${alertDescription}_${alertName}"
        is ConnectionReset -> "RST"
        is Timeout -> "TIMEOUT"
        is UnexpectedEof -> "EOF"
        is IoError -> "IO:${cause.take(40)}"
    }
}

/**
 * Outcome of a raw-socket probe initiated via [TlsConnector.probeRawAfterHello].
 *
 * Unlike [HandshakeResult] (which uses BCTLS), this variant gives callers direct
 * access to the server's raw response bytes so they can inspect TLS record content
 * that BCTLS would normally hide (e.g. Heartbeat reply memory, SSLv2 server-hello).
 */
sealed class RawProbeOutcome {

    /**
     * The probe completed without I/O error.
     *
     * @param handshakePhase Server bytes received in response to our ClientHello.
     * @param afterHandshake Server bytes received after we sent [payloadAfterHandshake].
     *                       Empty if [payloadAfterHandshake] was empty or the server
     *                       sent nothing back.
     */
    data class Ok(
        val handshakePhase: ByteArray,
        val afterHandshake: ByteArray,
    ) : RawProbeOutcome() {
        override fun equals(other: Any?): Boolean = false   // ByteArray identity not useful
        override fun hashCode(): Int =
            handshakePhase.contentHashCode() xor afterHandshake.contentHashCode()
    }

    /** The probe could not be completed due to a network or connection error. */
    data class Error(val message: String) : RawProbeOutcome()
}
