package io.safebyte.tlsinspector.probes

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
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * ALPACA — Application Layer Protocol Confusion Attack (CVE-2021-3618).
 *
 * If a TLS certificate covers both web (HTTPS) hostnames and non-web protocol
 * hostnames (SMTP, IMAP, FTP, etc.), an attacker who can redirect traffic
 * (DNS or BGP hijacking) can relay a HTTPS connection to an email/FTP server
 * that shares the same certificate — achieving cross-protocol confusion.
 *
 * Detection: parse server leaf certificate SAN extension, look for DNS names
 * belonging to non-web protocols (mail.*, smtp.*, ftp.*, imap.*, pop3.*, etc.)
 * A cert that covers e.g. "mail.example.com" alongside "www.example.com"
 * enables ALPACA if strict ALPN is not enforced.
 *
 * Reports POTENTIALLY_VULNERABLE based on SAN scope — wire-level ALPN check deferred.
 */
class AlpacaProbe : TlsProbe {
    override val id = "ALPACA"
    override val displayName = "ALPACA Cross-Protocol Confusion (CVE-2021-3618)"
    override val kind = ProbeKind.VULNERABILITY

    private val NON_WEB_PREFIXES = listOf(
        "mail.", "smtp.", "imap.", "pop.", "pop3.", "ftp.", "sftp.", "ftps.",
        "mx.", "relay.", "exchange.", "webmail.", "owa.", "autodiscover.",
        "submission.", "outbound-smtp.", "inbound-smtp."
    )

    private val NON_WEB_LABELS = setOf(
        "mail", "smtp", "imap", "pop", "pop3", "ftp", "sftp", "ftps",
        "mx", "relay", "exchange", "webmail", "owa", "autodiscover"
    )

    override fun run(ctx: ProbeContext, result: TlsScanResult): List<TlsFinding> =
        runWithResult(ctx, result).findings

    override fun runWithResult(ctx: ProbeContext, result: TlsScanResult): ProbeResult {
        val started = System.currentTimeMillis()

        val chain = fetchCertChain(ctx, result)
            ?: return ProbeResult.error(id, displayName,
                "Could not complete TLS handshake to retrieve certificate",
                System.currentTimeMillis() - started)

        if (chain.isEmpty()) {
            return ProbeResult.error(id, displayName,
                "Server sent no certificate",
                System.currentTimeMillis() - started)
        }

        return try {
            analyzeLeafCert(chain[0], result, started)
        } catch (e: Exception) {
            ProbeResult.error(id, displayName,
                "Certificate parse error: ${e.javaClass.simpleName}: ${e.message}",
                System.currentTimeMillis() - started)
        }
    }

    private fun fetchCertChain(ctx: ProbeContext, result: TlsScanResult): List<ByteArray>? {
        return try {
            // Pick highest offered TLS version (prefer TLS 1.2 for broad cert extension support)
            val version = when {
                result.protocolsOffered[TlsProtocol.TLS_1_2] == ProtocolStatus.OFFERED -> TlsProtocol.TLS_1_2
                result.protocolsOffered[TlsProtocol.TLS_1_3] == ProtocolStatus.OFFERED -> TlsProtocol.TLS_1_3
                result.protocolsOffered[TlsProtocol.TLS_1_1] == ProtocolStatus.OFFERED -> TlsProtocol.TLS_1_1
                result.protocolsOffered[TlsProtocol.TLS_1_0] == ProtocolStatus.OFFERED -> TlsProtocol.TLS_1_0
                else -> TlsProtocol.TLS_1_2  // default attempt
            }
            val timeoutMs = ctx.budget.handshakeTimeout.toMillis().toInt()
            val sock = TlsRawSocket.openSocket(ctx)
            sock.use {
                val hello = ClientHelloBuilder.build(
                    version = version,
                    sni = ctx.sni,
                    cipherSuites = ClientHelloBuilder.DEFAULT_CIPHER_SUITES,
                )
                sock.getOutputStream().write(hello)
                sock.getOutputStream().flush()
                val (rawBuf, seenDone) = TlsRawSocket.readUntilServerHelloDone(sock, timeoutMs)
                if (!seenDone && rawBuf.isEmpty()) return@use null
                val chain = HandshakeParser.extractCertChain(rawBuf)
                chain.ifEmpty { null }
            }
        } catch (_: Exception) { null }
    }

    private fun analyzeLeafCert(derBytes: ByteArray, result: TlsScanResult, started: Long): ProbeResult {
        val cf = CertificateFactory.getInstance("X.509")
        val cert = cf.generateCertificate(derBytes.inputStream()) as X509Certificate

        val dnsSans = mutableListOf<String>()
        cert.subjectAlternativeNames?.forEach { entry ->
            val type = (entry[0] as? Int) ?: return@forEach
            val value = (entry[1] as? String) ?: return@forEach
            if (type == 2) dnsSans += value.lowercase()
        }

        if (dnsSans.isEmpty()) {
            val cn = cert.subjectX500Principal.name
                .split(",")
                .firstOrNull { it.trimStart().startsWith("CN=") }
                ?.substringAfter("CN=")?.trim()?.lowercase()
            if (cn != null) dnsSans += cn
        }

        val offendingSans = dnsSans.filter { san -> isNonWebHostname(san) }
        val isWildcard = dnsSans.any { it.startsWith("*.") }
        val wildcardRisk = isWildcard && dnsSans.any { !it.startsWith("*.") }

        return when {
            offendingSans.isNotEmpty() -> {
                val finding = TlsFinding(
                    id = "ALPACA:non_web_san_in_cert",
                    title = "ALPACA: Certificate SAN Covers Non-Web Protocol Hostnames (CVE-2021-3618)",
                    severity = TlsSeverity.MEDIUM,
                    confidence = TlsConfidence.FIRM,
                    descriptionHtml = """
                        <p><b>Summary:</b> The server certificate's Subject Alternative Names include
                        non-web protocol hostnames: <b>${offendingSans.joinToString()}</b>.</p>
                        <p>All SANs: <code>${dnsSans.joinToString()}</code></p>
                        <p>The ALPACA attack (CVE-2021-3618) exploits TLS servers that share certificates
                        across different application protocols (HTTPS, SMTP, FTP, IMAP). An attacker who
                        can redirect traffic (DNS hijacking, BGP poisoning) can relay a HTTPS connection
                        to a mail or FTP server that accepts the same certificate — bypassing application-
                        level authentication if ALPN is not enforced.</p>
                        <p>Cross-protocol confusion is feasible if the server does not enforce strict ALPN
                        (Application-Layer Protocol Negotiation) or if the client doesn't validate ALPN.</p>
                        <p><b>CVE:</b> CVE-2021-3618 | CVSS 7.4 (HIGH)</p>
                        <p><b>Compliance:</b> PCI DSS §4.2.1 (use of strong cryptographic protocols).</p>
                    """.trimIndent(),
                    remediationHtml = "<p>Issue separate certificates for each service type (web vs mail vs FTP). " +
                        "Enforce strict ALPN on both client and server. " +
                        "See: <a href=\"https://alpaca-attack.com/\">alpaca-attack.com</a></p>",
                    references = listOf(
                        "https://alpaca-attack.com/",
                        "https://nvd.nist.gov/vuln/detail/CVE-2021-3618",
                    )
                )
                synchronized(result) { result.findings.add(finding) }
                ProbeResult.potentiallyVulnerable(id, displayName, listOf(finding),
                    System.currentTimeMillis() - started,
                    "Certificate SAN covers non-web hostnames: ${offendingSans.joinToString()}")
            }
            wildcardRisk -> {
                val wildcardSan = dnsSans.firstOrNull { it.startsWith("*.") } ?: "*.?"
                val finding = TlsFinding(
                    id = "ALPACA:wildcard_cert_non_web_risk",
                    title = "ALPACA: Wildcard Certificate May Cover Non-Web Services (CVE-2021-3618)",
                    severity = TlsSeverity.LOW,
                    confidence = TlsConfidence.TENTATIVE,
                    descriptionHtml = """
                        <p><b>Summary:</b> The server uses a wildcard certificate
                        (<code>$wildcardSan</code>) that could cover non-web service subdomains.
                        ALPN enforcement was not verified at the wire level.</p>
                        <p>All SANs: <code>${dnsSans.joinToString()}</code></p>
                        <p>ALPACA (CVE-2021-3618) is potentially relevant if any subdomain of this
                        wildcard is used for non-web services (SMTP, IMAP, FTP) sharing the same
                        certificate.</p>
                    """.trimIndent(),
                    remediationHtml = "<p>Avoid wildcard certificates that span multiple service types. " +
                        "Enforce strict ALPN. Issue separate certificates per service.</p>",
                    references = listOf(
                        "https://alpaca-attack.com/",
                        "https://nvd.nist.gov/vuln/detail/CVE-2021-3618",
                    )
                )
                synchronized(result) { result.findings.add(finding) }
                ProbeResult.potentiallyVulnerable(id, displayName, listOf(finding),
                    System.currentTimeMillis() - started,
                    "Wildcard cert $wildcardSan — potential non-web service overlap")
            }
            else -> ProbeResult.notVulnerable(id, displayName, System.currentTimeMillis() - started)
        }
    }

    private fun isNonWebHostname(name: String): Boolean {
        if (NON_WEB_PREFIXES.any { name.startsWith(it) }) return true
        val firstLabel = name.substringBefore(".")
        return firstLabel in NON_WEB_LABELS
    }
}
