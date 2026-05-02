package io.safebyte.tlsinspector.probes

import io.safebyte.tlsinspector.CipherFlag
import io.safebyte.tlsinspector.ClientHelloBuilder
import io.safebyte.tlsinspector.HandshakeParser
import io.safebyte.tlsinspector.ProbeContext
import io.safebyte.tlsinspector.ProtocolStatus
import io.safebyte.tlsinspector.TlsConfidence
import io.safebyte.tlsinspector.TlsProtocol
import io.safebyte.tlsinspector.TlsRawSocket
import io.safebyte.tlsinspector.TlsScanResult
import io.safebyte.tlsinspector.TlsSeverity
import io.safebyte.tlsinspector.reporting.TlsFinding
import java.math.BigInteger
import java.net.Socket
import java.net.SocketTimeoutException

/**
 * ROBOT — Return Of Bleichenbacher's Oracle Threat (CVE-2017-13099 family).
 *
 * Technique (ported from validated standalone):
 * 1. Complete a TLS 1.2 RSA handshake to extract the server's RSA public key.
 * 2. Craft 5 PKCS#1 v1.5 ClientKeyExchange variants with intentional padding flaws.
 * 3. Send each to a fresh handshake (CKE + CCS + junk Finished).
 * 4. If all 5 responses are identical → no oracle (NOT_VULNERABLE).
 *    If responses differ → re-probe to confirm → classify WEAK/STRONG oracle.
 *
 * Pre-condition: TLS 1.2 must be offered with at least one TLS_RSA_* cipher.
 */
class RobotProbe : TlsProbe {
    override val id = "ROBOT"
    override val displayName = "ROBOT (CVE-2017-13099)"
    override val kind = ProbeKind.VULNERABILITY

    // PMS bytes — mirrors sslyze _RobotTlsRecordPayloads
    private val PMS_BYTES = byteArrayOf(
        0xaa.toByte(), 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88.toByte(), 0x99.toByte(),
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88.toByte(), 0x99.toByte(), 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88.toByte(), 0x99.toByte(), 0x11, 0x22,
        0x33, 0x44, 0x55, 0x66, 0x77, 0x88.toByte(), 0x99.toByte(), 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77, 0x88.toByte(), 0x99.toByte()
    ) // 46 bytes

    private val JUNK_FINISHED = byteArrayOf(
        0x16, 0x03, 0x03, 0x00, 0x28,
        0x14,
        0x00, 0x00, 0x24,
        *ByteArray(36) { 0x00 }
    )

    private val CCS_RECORD = byteArrayOf(0x14, 0x03, 0x03, 0x00, 0x01, 0x01)

    override fun run(ctx: ProbeContext, result: TlsScanResult): List<TlsFinding> =
        runWithResult(ctx, result).findings

    override fun runWithResult(ctx: ProbeContext, result: TlsScanResult): ProbeResult {
        val started = System.currentTimeMillis()

        if (result.protocolsOffered[TlsProtocol.TLS_1_2] != ProtocolStatus.OFFERED) {
            return ProbeResult.notApplicable(id, displayName,
                "TLS 1.2 not offered — ROBOT requires RSA key-exchange via TLS 1.2",
                System.currentTimeMillis() - started)
        }

        // Check if server has any static-RSA cipher suites (no DHE/ECDHE forward secrecy)
        // Static RSA key exchange: no FORWARD_SECRECY flag and no ANON_KX — server's cert RSA key is used
        val rsaCiphers = result.ciphersByProtocol[TlsProtocol.TLS_1_2]
            ?.filter { c ->
                CipherFlag.FORWARD_SECRECY !in c.flags &&
                CipherFlag.ANON_KX !in c.flags &&
                (c.name.contains("TLS_RSA_") || c.keyExchange == "RSA")
            }
            ?: emptyList()

        if (rsaCiphers.isEmpty()) {
            return ProbeResult.notApplicable(id, displayName,
                "No TLS_RSA_* (static RSA) cipher suites offered on TLS 1.2",
                System.currentTimeMillis() - started)
        }

        return try {
            runRobotCheck(ctx, result, started)
        } catch (e: Exception) {
            ProbeResult.error(id, displayName,
                "ROBOT probe error: ${e.javaClass.simpleName}: ${e.message}",
                System.currentTimeMillis() - started)
        }
    }

    private fun extractServerRsaKey(ctx: ProbeContext): Pair<BigInteger, BigInteger>? {
        val sock = TlsRawSocket.openSocket(ctx)
        return sock.use {
            sock.getOutputStream().write(ClientHelloBuilder.buildRsaOnlyClientHello(ctx.sni))
            sock.getOutputStream().flush()
            val timeoutMs = ctx.budget.handshakeTimeout.toMillis().toInt()
            val (rawBuf, seenDone) = TlsRawSocket.readUntilServerHelloDone(sock, timeoutMs)
            if (!seenDone) return@use null
            val chain = HandshakeParser.extractCertChain(rawBuf)
            HandshakeParser.extractRsaPublicKey(chain)
        }
    }

    private fun buildEncryptedPms(variant: Int, modulus: BigInteger, exponent: BigInteger): ByteArray {
        val modLen = (modulus.bitLength() + 7) / 8
        val padLen = modLen - 3 - 1 - 2 - PMS_BYTES.size   // = modLen - 52

        val plain = when (variant) {
            0 -> byteArrayOf(0x00, 0x02) + ByteArray(padLen) { 0xab.toByte() } + byteArrayOf(0x00, 0x03, 0x03) + PMS_BYTES
            1 -> byteArrayOf(0x41, 0x17) + ByteArray(padLen) { 0xab.toByte() } + byteArrayOf(0x00, 0x03, 0x03) + PMS_BYTES
            2 -> byteArrayOf(0x00, 0x02) + ByteArray(padLen) { 0xab.toByte() } + byteArrayOf(0x11) + PMS_BYTES + byteArrayOf(0x00, 0x11)
            3 -> byteArrayOf(0x00, 0x02) + ByteArray(padLen) { 0xab.toByte() } + byteArrayOf(0x11, 0x11, 0x11) + PMS_BYTES
            else -> byteArrayOf(0x00, 0x02) + ByteArray(padLen) { 0xab.toByte() } + byteArrayOf(0x00, 0x02, 0x02) + PMS_BYTES
        }

        val m = BigInteger(1, plain)
        val c = m.modPow(exponent, modulus)
        val cBytes = c.toByteArray().let { ba ->
            when {
                ba.size == modLen + 1 && ba[0] == 0.toByte() -> ba.copyOfRange(1, ba.size)
                ba.size < modLen -> ByteArray(modLen - ba.size) + ba
                else -> ba
            }
        }
        return cBytes
    }

    private fun probeOracle(ctx: ProbeContext, encryptedPms: ByteArray): String {
        return try {
            val sock = TlsRawSocket.openSocket(ctx)
            sock.use {
                sock.getOutputStream().write(ClientHelloBuilder.buildRsaOnlyClientHello(ctx.sni))
                sock.getOutputStream().flush()
                val timeoutMs = ctx.budget.handshakeTimeout.toMillis().toInt()
                val (_, seenDone) = TlsRawSocket.readUntilServerHelloDone(sock, timeoutMs)
                if (!seenDone) return@use "no_server_hello_done"

                val ckeRecord = ClientHelloBuilder.buildClientKeyExchangeRsa(encryptedPms)
                sock.getOutputStream().write(ckeRecord)
                sock.getOutputStream().write(CCS_RECORD)
                sock.getOutputStream().write(JUNK_FINISHED)
                sock.getOutputStream().flush()

                readOracleResponse(sock, 2000)
            }
        } catch (e: java.net.ConnectException) {
            "connection_refused"
        } catch (e: Exception) {
            "error:${e.javaClass.simpleName}"
        }
    }

    private fun readOracleResponse(sock: Socket, timeoutMs: Int): String {
        sock.soTimeout = timeoutMs
        return try {
            val record = TlsRawSocket.readTlsRecord(sock, timeoutMs) ?: return "eof"
            val rt = record[0].toInt() and 0xFF
            when (rt) {
                0x15 -> if (record.size >= 7) "alert_${record[6].toInt() and 0xFF}" else "alert_unknown"
                0x16 -> "handshake"
                0x14 -> "ccs"
                else -> "record_$rt"
            }
        } catch (e: SocketTimeoutException) {
            "timeout"
        } catch (e: java.io.IOException) {
            "rst"
        }
    }

    private fun runRobotCheck(ctx: ProbeContext, result: TlsScanResult, started: Long): ProbeResult {
        val keyPair = extractServerRsaKey(ctx)
            ?: return ProbeResult.notApplicable(id, displayName,
                "Could not complete RSA handshake to extract server key",
                System.currentTimeMillis() - started)

        val (modulus, exponent) = keyPair
        val variants = (0..4).map { v -> buildEncryptedPms(v, modulus, exponent) }

        // First pass
        val responses = variants.map { encPms -> probeOracle(ctx, encPms) }
        if (responses.toSet().size == 1) {
            return ProbeResult.notVulnerable(id, displayName, System.currentTimeMillis() - started)
        }

        // Re-probe to confirm (avoid transient network differences)
        val responses2 = variants.map { encPms -> probeOracle(ctx, encPms) }
        if (responses2.toSet().size == 1) {
            return ProbeResult.notVulnerable(id, displayName, System.currentTimeMillis() - started)
        }

        // Classify oracle strength
        val r1 = responses2[1]; val r2 = responses2[2]; val r3 = responses2[3]
        val strength = if (r1 == r2 && r2 == r3) "WEAK" else "STRONG"

        val finding = TlsFinding(
            id = "ROBOT:bleichenbacher_oracle_${strength.lowercase()}",
            title = "ROBOT: Bleichenbacher RSA Oracle ($strength) — CVE-2017-13099",
            severity = TlsSeverity.CRITICAL,
            confidence = TlsConfidence.CERTAIN,
            descriptionHtml = """
                <p><b>Summary:</b> The server exhibits a Bleichenbacher RSA padding oracle ($strength).
                ROBOT (Return Of Bleichenbacher's Oracle Threat) allows an attacker to decrypt RSA-encrypted
                TLS sessions and forge RSA signatures without the private key.</p>
                <p>Oracle detection: 5 PKCS#1 v1.5 variants were sent. Responses differed across two
                independent passes, confirming a distinguishable oracle.</p>
                <p>Variant responses: valid=${responses2[0]}, bad1=$r1, bad2=$r2,
                bad3=$r3, bad4=${responses2[4]}</p>
                <p><b>CVE:</b> CVE-2017-13099 (F5/Citrix/Cisco/Radware/Erlang). CVSS 7.5 (HIGH).</p>
                <p><b>Compliance:</b> PCI DSS §6.3 — critical vulnerability, patch immediately.</p>
            """.trimIndent(),
            remediationHtml = "<p>Disable all <code>TLS_RSA_*</code> cipher suites (static RSA key exchange). " +
                "Enable only ECDHE/DHE suites. Apply vendor patches for CVE-2017-13099. " +
                "See: <a href=\"https://robotattack.org/\">robotattack.org</a></p>",
            references = listOf(
                "https://nvd.nist.gov/vuln/detail/CVE-2017-13099",
                "https://robotattack.org/",
            )
        )
        synchronized(result) { result.findings.add(finding) }
        return ProbeResult.vulnerable(id, displayName, listOf(finding),
            System.currentTimeMillis() - started,
            "Bleichenbacher oracle ($strength) — RSA CKE distinguishable responses")
    }
}
