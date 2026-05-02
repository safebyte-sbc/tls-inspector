package io.safebyte.tlsinspector

import burp.api.montoya.MontoyaApi
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import java.time.Duration

/**
 * Shared context handed to every probe. Probes MUST NOT mutate this object.
 */
data class ProbeContext(
    val host: String,
    val port: Int,
    val sni: String,
    val api: MontoyaApi,
    val budget: ScanBudget,
    val cancelled: () -> Boolean,
    val allowExternalQueries: Boolean = true,
    val profile: ScanProfile = ScanProfile.MOZILLA_INTERMEDIATE,
    /** When true, CT-discovered subdomains are auto-injected into Burp site map after scan. */
    val injectCtIntoSiteMap: Boolean = true,
)

/** Per-scan time budget. fast/normal/thorough mirror Burp's scan_speed. */
enum class ScanBudget(
    val handshakeTimeout: Duration,
    val perProbeTimeout: Duration,
    val maxConcurrentHandshakes: Int
) {
    FAST(Duration.ofSeconds(3), Duration.ofSeconds(15), 4),
    NORMAL(Duration.ofSeconds(5), Duration.ofSeconds(45), 4),
    THOROUGH(Duration.ofSeconds(10), Duration.ofSeconds(180), 2)
}

enum class TlsSeverity {
    CRITICAL, HIGH, MEDIUM, LOW, INFO;

    fun toBurp(): AuditIssueSeverity = when (this) {
        CRITICAL, HIGH -> AuditIssueSeverity.HIGH
        MEDIUM -> AuditIssueSeverity.MEDIUM
        LOW -> AuditIssueSeverity.LOW
        INFO -> AuditIssueSeverity.INFORMATION
    }
}

enum class TlsConfidence {
    CERTAIN, FIRM, TENTATIVE;

    fun toBurp(): AuditIssueConfidence = when (this) {
        CERTAIN -> AuditIssueConfidence.CERTAIN
        FIRM -> AuditIssueConfidence.FIRM
        TENTATIVE -> AuditIssueConfidence.TENTATIVE
    }
}
