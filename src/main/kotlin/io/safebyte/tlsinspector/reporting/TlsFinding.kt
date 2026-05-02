package io.safebyte.tlsinspector.reporting

import io.safebyte.tlsinspector.TlsConfidence
import io.safebyte.tlsinspector.TlsSeverity

/**
 * Internal finding model. Converted to a Burp AuditIssue by TlsIssueBuilder.
 *
 * @param id format: "PROBE_NAME:specific_key" (e.g. "PROTOCOL_ENUM:tls10_offered"); used for dedup
 * @param descriptionHtml full HTML body shown in Burp issue detail pane
 * @param remediationHtml HTML remediation guidance (may be null)
 * @param references list of URLs (RFC, NVD, vendor advisories)
 * @param evidence raw evidence (cert PEM, alert codes, etc.) — surfaced in tab UI only
 */
data class TlsFinding(
    val id: String,
    val title: String,
    val severity: TlsSeverity,
    val confidence: TlsConfidence,
    val descriptionHtml: String,
    val remediationHtml: String? = null,
    val references: List<String> = emptyList(),
    val evidence: Map<String, String> = emptyMap()
)
