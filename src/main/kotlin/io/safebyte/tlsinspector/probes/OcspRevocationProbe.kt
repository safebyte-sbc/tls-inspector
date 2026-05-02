package io.safebyte.tlsinspector.probes

import io.safebyte.tlsinspector.ProbeContext
import io.safebyte.tlsinspector.TlsConfidence
import io.safebyte.tlsinspector.TlsScanResult
import io.safebyte.tlsinspector.TlsSeverity
import io.safebyte.tlsinspector.reporting.TlsFinding
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.ocsp.CertificateID
import org.bouncycastle.cert.ocsp.OCSPReqBuilder
import org.bouncycastle.cert.ocsp.OCSPResp
import org.bouncycastle.cert.ocsp.RevokedStatus
import org.bouncycastle.cert.ocsp.BasicOCSPResp
import org.bouncycastle.cert.ocsp.UnknownStatus
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider
import java.io.DataOutputStream
import java.net.HttpURLConnection
import java.net.URL

/**
 * OCSP Revocation Probe — checks whether the leaf certificate is revoked via OCSP.
 *
 * Technique:
 * 1. Parse the leaf certificate's AIA extension to obtain the OCSP responder URL.
 * 2. Parse the issuer certificate from the chain (index 1) or skip if chain is incomplete.
 * 3. Build an OCSP request using BouncyCastle OCSPReqBuilder.
 * 4. POST to the OCSP responder and parse the response.
 *
 * Gaps documented:
 * - When issuer cert is missing from the chain (AIA caIssuers fetch not implemented),
 *   the probe returns NOT_APPLICABLE.
 * - OCSP nonce verification not enforced (anti-replay gap).
 * - CRL signature verification deferred — trust CA URL implicitly.
 */
class OcspRevocationProbe : TlsProbe {
    override val id = "OCSP_REVOCATION"
    override val displayName = "OCSP Revocation Check"
    override val kind = ProbeKind.INFORMATIONAL

    override fun run(ctx: ProbeContext, result: TlsScanResult): List<TlsFinding> =
        runWithResult(ctx, result).findings

    override fun runWithResult(ctx: ProbeContext, result: TlsScanResult): ProbeResult {
        val started = System.currentTimeMillis()
        val elapsed = { System.currentTimeMillis() - started }

        if (!ctx.allowExternalQueries) {
            return ProbeResult.notApplicable(id, displayName,
                "External queries disabled in ProbeContext", elapsed())
        }

        val leaf = result.leafCertificate
            ?: return ProbeResult.notApplicable(id, displayName,
                "No leaf certificate captured — run CERT_VALIDATION probe first", elapsed())

        val ocspUrls = leaf.authorityInfoAccess?.ocspUrls ?: emptyList()
        if (ocspUrls.isEmpty()) {
            return ProbeResult.notApplicable(id, displayName,
                "No OCSP URL in certificate AIA extension", elapsed())
        }

        val issuerDer = result.certificateChain.getOrNull(1)?.derEncoded
            ?: return ProbeResult.notApplicable(id, displayName,
                "Issuer certificate not in chain — AIA caIssuers fetch not implemented (MS E gap)", elapsed())

        return try {
            val leafHolder = X509CertificateHolder(leaf.derEncoded)
            val issuerHolder = X509CertificateHolder(issuerDer)

            val digestCalcProvider = BcDigestCalculatorProvider()
            val digestCalc = digestCalcProvider.get(CertificateID.HASH_SHA1)
            val certId = CertificateID(digestCalc, issuerHolder, leafHolder.serialNumber)

            val req = OCSPReqBuilder().addRequest(certId).build()
            val reqBytes = req.encoded

            val ocspUrl = ocspUrls.first()
            val response = queryOcsp(ocspUrl, reqBytes,
                ctx.budget.handshakeTimeout.toMillis().toInt())

            buildResult(response, certId, elapsed())
        } catch (e: Exception) {
            ProbeResult.error(id, displayName, "OCSP query failed: ${e.message}", elapsed())
        }
    }

    private fun queryOcsp(url: String, reqBytes: ByteArray, timeoutMs: Int): OCSPResp {
        val conn = URL(url).openConnection() as HttpURLConnection
        conn.connectTimeout = timeoutMs
        conn.readTimeout = timeoutMs
        conn.doOutput = true
        conn.requestMethod = "POST"
        conn.setRequestProperty("Content-Type", "application/ocsp-request")
        conn.setRequestProperty("Accept", "application/ocsp-response")
        DataOutputStream(conn.outputStream).use { it.write(reqBytes) }
        val respBytes = conn.inputStream.use { it.readBytes() }
        return OCSPResp(respBytes)
    }

    private fun buildResult(ocspResp: OCSPResp, certId: CertificateID, ms: Long): ProbeResult {
        if (ocspResp.status != OCSPResponseStatus.SUCCESSFUL) {
            return ProbeResult.notApplicable(id, displayName,
                "OCSP responder returned non-success status: ${ocspResp.status}", ms)
        }

        val basicResp = ocspResp.responseObject as? BasicOCSPResp
            ?: return ProbeResult.error(id, displayName, "Unexpected OCSP response type", ms)

        // Match by serial number — we trust the OCSP responder to be the correct issuer's responder
        // since we fetched the URL from the certificate's AIA extension.
        val singleResp = basicResp.responses.firstOrNull { resp ->
            resp.certID.serialNumber == certId.serialNumber
        } ?: return ProbeResult.error(id, displayName, "Certificate ID not found in OCSP response", ms)

        return when (val certStatus = singleResp.certStatus) {
            null -> {
                // null certStatus == Good (per RFC 6960 §4.2.1)
                ProbeResult.notVulnerable(id, displayName, ms)
                    .copy(message = "OCSP: Certificate is GOOD (not revoked)")
            }
            is RevokedStatus -> {
                val reason = certStatus.revocationReason
                val revokedAt = certStatus.revocationTime
                val finding = TlsFinding(
                    id = "OCSP_REVOCATION:certificate_revoked",
                    title = "Certificate Revoked (OCSP)",
                    severity = TlsSeverity.CRITICAL,
                    confidence = TlsConfidence.CERTAIN,
                    descriptionHtml = """
                        <p><b>Summary:</b> The server certificate has been explicitly revoked by its
                        issuing Certificate Authority. Clients that perform OCSP or CRL checking will
                        reject this certificate, breaking the TLS handshake.</p>
                        <p><b>Revoked at:</b> $revokedAt</p>
                        <p><b>Reason code:</b> $reason (RFC 5280 §5.3.1: 0=unspecified,
                        1=keyCompromise, 3=affiliationChanged, 4=superseded,
                        5=cessationOfOperation)</p>
                        <p><b>Compliance impact:</b> PCI DSS §6.3.3 (invalid certificate in use).
                        ETSI TS 119 312 §6.5 (revoked certificate violates trust chain).</p>
                    """.trimIndent(),
                    remediationHtml = "<p>Replace the certificate immediately. If the revocation " +
                        "reason is keyCompromise (1), rotate the private key before re-issuing. " +
                        "Investigate the incident that caused revocation.</p>",
                    references = listOf(
                        "https://datatracker.ietf.org/doc/html/rfc5280#section-5.3.1",
                        "https://datatracker.ietf.org/doc/html/rfc6960",
                    )
                )
                ProbeResult.vulnerable(id, displayName, listOf(finding), ms,
                    "Certificate is REVOKED by OCSP (revoked at $revokedAt, reason=$reason)")
            }
            is UnknownStatus -> {
                ProbeResult.notApplicable(id, displayName,
                    "OCSP responder returned UNKNOWN status for this certificate", ms)
            }
            else -> {
                ProbeResult.notApplicable(id, displayName,
                    "Unhandled OCSP cert status type: ${certStatus::class.simpleName}", ms)
            }
        }
    }
}
