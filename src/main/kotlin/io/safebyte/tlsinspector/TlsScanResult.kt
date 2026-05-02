package io.safebyte.tlsinspector

import io.safebyte.tlsinspector.certificate.ParsedCertificate
import io.safebyte.tlsinspector.reporting.TlsFinding
import java.time.Instant

/** Aggregated scan result, populated incrementally by TlsScanRunner. */
data class TlsScanResult(
    val target: String,
    val startedAt: Instant,
    var finishedAt: Instant? = null,
    val protocolsOffered: MutableMap<TlsProtocol, ProtocolStatus> = mutableMapOf(),
    val ciphersByProtocol: MutableMap<TlsProtocol, List<CipherSuiteResult>> = mutableMapOf(),
    var leafCertificate: ParsedCertificate? = null,
    var certificateChain: List<ParsedCertificate> = emptyList(),
    val findings: MutableList<TlsFinding> = mutableListOf(),
    val probeResults: MutableList<io.safebyte.tlsinspector.probes.ProbeResult> = mutableListOf(),
    val errors: MutableList<String> = mutableListOf(),
    /** Subdomains discovered via Certificate Transparency log queries (CT log probe). */
    var ctSubdomains: List<String> = emptyList(),
)

enum class TlsProtocol(
    val displayName: String,
    val isDeprecated: Boolean,
    val major: Int,
    val minor: Int,
) {
    SSL_2_0("SSLv2",   true,  0x02, 0x00),
    SSL_3_0("SSLv3",   true,  0x03, 0x00),
    TLS_1_0("TLS 1.0", true,  0x03, 0x01),
    TLS_1_1("TLS 1.1", true,  0x03, 0x02),
    TLS_1_2("TLS 1.2", false, 0x03, 0x03),
    TLS_1_3("TLS 1.3", false, 0x03, 0x04),
}

enum class ProtocolStatus { OFFERED, NOT_OFFERED, ERROR }

data class CipherSuiteResult(
    val name: String,
    val openSslName: String?,
    val keyExchange: String,
    val authentication: String,
    val encryption: String,
    val mac: String,
    val grade: CipherGrade,
    val flags: Set<CipherFlag> = emptySet()
)

enum class CipherGrade { STRONG, ACCEPTABLE, WEAK, INSECURE }

enum class CipherFlag {
    NULL_CIPHER, ANON_KX, EXPORT_GRADE, RC4, TRIPLE_DES_64BIT_BLOCK,
    CBC_NO_AEAD, FORWARD_SECRECY, AEAD, POST_QUANTUM_HYBRID
}
