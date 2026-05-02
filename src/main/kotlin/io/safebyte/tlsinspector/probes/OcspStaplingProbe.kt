package io.safebyte.tlsinspector.probes

import io.safebyte.tlsinspector.HandshakeResult
import io.safebyte.tlsinspector.ProbeContext
import io.safebyte.tlsinspector.TlsConfidence
import io.safebyte.tlsinspector.TlsConnector
import io.safebyte.tlsinspector.TlsProtocol
import io.safebyte.tlsinspector.TlsScanResult
import io.safebyte.tlsinspector.TlsSeverity
import io.safebyte.tlsinspector.reporting.TlsFinding

/**
 * OCSP Stapling Probe — checks whether the server staples an OCSP response in the TLS handshake.
 *
 * Technique:
 * 1. Perform a TLS handshake that includes the status_request extension (type 0x0005 = RFC 6066).
 * 2. Check whether the server includes extension 0x0005 in its ServerHello.
 *    Extension 0x0005 presence in the server response indicates the server provided a
 *    Certificate Status (status_request) response, which means it is stapling an OCSP response.
 *
 * Note: This probe checks for server support of status_request (RFC 6066), not the full
 * OCSP response content. Absence of stapling is LOW severity (not a vulnerability per se,
 * but a missed opportunity to provide immediate revocation information without client queries).
 */
class OcspStaplingProbe : TlsProbe {
    override val id = "OCSP_STAPLING"
    override val displayName = "OCSP Stapling (RFC 6066 status_request)"
    override val kind = ProbeKind.INFORMATIONAL

    // TLS extension type: status_request (RFC 6066)
    private val STATUS_REQUEST_EXT = 0x0005

    override fun run(ctx: ProbeContext, result: TlsScanResult): List<TlsFinding> =
        runWithResult(ctx, result).findings

    override fun runWithResult(ctx: ProbeContext, result: TlsScanResult): ProbeResult {
        val started = System.currentTimeMillis()
        val elapsed = { System.currentTimeMillis() - started }

        // Only probe if TLS 1.2 or 1.3 is available (OCSP stapling defined for TLS 1.2+ in RFC 6066)
        val connector = TlsConnector(ctx)
        val proto = listOf(TlsProtocol.TLS_1_3, TlsProtocol.TLS_1_2)
            .firstOrNull { p ->
                result.protocolsOffered[p] == io.safebyte.tlsinspector.ProtocolStatus.OFFERED
            }

        if (proto == null) {
            return ProbeResult.notApplicable(id, displayName,
                "Neither TLS 1.2 nor TLS 1.3 offered — OCSP stapling not applicable", elapsed())
        }

        val handshakeResult = connector.probeHandshake(proto,
            io.safebyte.tlsinspector.TlsConfig.DEFAULT_CIPHER_SUITES_MODERN)

        return when (handshakeResult) {
            is HandshakeResult.Success -> {
                val staplingPresent = STATUS_REQUEST_EXT in handshakeResult.serverExtensions

                if (staplingPresent) {
                    // OCSP stapling is active — good security posture
                    val finding = TlsFinding(
                        id = "OCSP_STAPLING:stapling_active",
                        title = "OCSP Stapling Active (RFC 6066)",
                        severity = TlsSeverity.INFO,
                        confidence = TlsConfidence.CERTAIN,
                        descriptionHtml = """
                            <p><b>Summary:</b> The server staples an OCSP response in the TLS handshake
                            (status_request extension, RFC 6066). This allows clients to verify certificate
                            revocation status without making separate OCSP requests to the CA, improving
                            privacy and performance.</p>
                            <p><b>ServerHello extension 0x0005 detected</b> in the ${proto.displayName} handshake.</p>
                            <p><b>Security benefit:</b> Eliminates OCSP soft-fail behavior, prevents
                            OCSP response privacy leaks, and avoids CA availability as a dependency
                            during TLS handshake.</p>
                        """.trimIndent(),
                        references = listOf(
                            "https://datatracker.ietf.org/doc/html/rfc6066#section-8",
                            "https://wiki.mozilla.org/Security/Server_Side_TLS#OCSP_Stapling",
                        )
                    )
                    synchronized(result) { result.findings.add(finding) }
                    ProbeResult.notVulnerable(id, displayName, elapsed())
                        .copy(message = "OCSP stapling detected (extension 0x0005 in ServerHello)")
                } else {
                    // OCSP stapling not detected — informational finding
                    val finding = TlsFinding(
                        id = "OCSP_STAPLING:not_supported",
                        title = "OCSP Stapling Not Supported",
                        severity = TlsSeverity.LOW,
                        confidence = TlsConfidence.FIRM,
                        descriptionHtml = """
                            <p><b>Summary:</b> The server does not staple an OCSP response in the TLS
                            handshake (no status_request extension in ServerHello). Clients must make
                            separate OCSP requests to the CA's responder to verify revocation status.</p>
                            <p><b>Impact:</b> Without OCSP stapling, clients may:
                            <ul>
                            <li>Skip revocation checking (soft-fail, common in browsers)</li>
                            <li>Leak which sites users visit to the CA's OCSP responder</li>
                            <li>Experience TLS handshake delays waiting for the OCSP response</li>
                            </ul></p>
                            <p><b>Note:</b> This is an informational finding — not a vulnerability.
                            OCSP stapling is recommended by Mozilla SSL Configuration Generator,
                            PCI DSS (best practice), and ETSI TS 119 312 §6.5.</p>
                        """.trimIndent(),
                        remediationHtml = """
                            <p>Enable OCSP stapling on the server:</p>
                            <ul>
                            <li><b>Nginx:</b> <code>ssl_stapling on; ssl_stapling_verify on;</code></li>
                            <li><b>Apache:</b> <code>SSLUseStapling on; SSLStaplingCache shmcb:...</code></li>
                            <li><b>HAProxy:</b> Configure <code>ssl-default-bind-options</code> with OCSP stapling</li>
                            </ul>
                        """.trimIndent(),
                        references = listOf(
                            "https://datatracker.ietf.org/doc/html/rfc6066#section-8",
                            "https://wiki.mozilla.org/Security/Server_Side_TLS#OCSP_Stapling",
                            "https://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_stapling",
                        )
                    )
                    synchronized(result) { result.findings.add(finding) }
                    ProbeResult.potentiallyVulnerable(id, displayName, listOf(finding), elapsed(),
                        "OCSP stapling not detected (extension 0x0005 absent from ServerHello)")
                }
            }
            else -> ProbeResult.notApplicable(id, displayName,
                "Handshake failed: ${handshakeResult.canonicalSignature()}", elapsed())
        }
    }
}
