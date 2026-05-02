package io.safebyte.tlsinspector.probes

import io.safebyte.tlsinspector.HandshakeParams
import io.safebyte.tlsinspector.HandshakeResult
import io.safebyte.tlsinspector.ProbeContext
import io.safebyte.tlsinspector.TlsConfig
import io.safebyte.tlsinspector.TlsConfidence
import io.safebyte.tlsinspector.TlsConnector
import io.safebyte.tlsinspector.TlsScanResult
import io.safebyte.tlsinspector.TlsSeverity
import io.safebyte.tlsinspector.certificate.CertificateAnomalyDetector
import io.safebyte.tlsinspector.certificate.CertificateChainAnalyzer
import io.safebyte.tlsinspector.certificate.CertificateInspector
import io.safebyte.tlsinspector.reporting.TlsFinding

class CertificateValidationProbe : TlsProbe {
    override val id = TlsConfig.PROBE_CERT_VALIDATION
    override val displayName = "Certificate Validation"
    override val kind = ProbeKind.INFORMATIONAL

    override fun run(ctx: ProbeContext, result: TlsScanResult): List<TlsFinding> {
        if (ctx.cancelled()) return emptyList()
        val connector = TlsConnector(ctx)
        val res = connector.attempt(HandshakeParams.modern(ctx.sni))

        if (res !is HandshakeResult.Success) {
            result.errors += "Certificate probe handshake failed: $res"
            return emptyList()
        }
        if (res.serverCertificateChain.isEmpty()) {
            result.errors += "Server returned empty certificate chain"
            return emptyList()
        }

        val chain = res.serverCertificateChain
            .take(TlsConfig.MAX_CHAIN_LENGTH)
            .map { CertificateInspector.parse(it) }
        val leaf = chain.first()
        result.leafCertificate = leaf
        result.certificateChain = chain

        val findings = mutableListOf<TlsFinding>()

        // Anomaly detection on leaf certificate
        findings += CertificateAnomalyDetector.detect(leaf, ctx.host)

        // Chain analysis
        val chainAnalysis = CertificateChainAnalyzer.analyze(chain)
        if (!chainAnalysis.isValid) findings += TlsFinding(
            id = "CERT_CHAIN:invalid",
            title = "Certificate Chain Validation Failed",
            severity = TlsSeverity.HIGH,
            confidence = TlsConfidence.FIRM,
            descriptionHtml = "<p>Chain failed PKIX validation: ${chainAnalysis.validationErrors.joinToString("; ")}</p>"
        )
        if (chainAnalysis.missingIntermediate) findings += TlsFinding(
            id = "CERT_CHAIN:missing_intermediates",
            title = "Server Did Not Send Intermediate Certificates",
            severity = TlsSeverity.MEDIUM,
            confidence = TlsConfidence.FIRM,
            descriptionHtml = "<p>Server returned only the leaf certificate. Browsers may fail validation if AIA fetch is disabled.</p>"
        )
        synchronized(result) { result.findings += findings }
        return findings
    }
}
