package io.safebyte.tlsinspector.compliance

import io.safebyte.tlsinspector.TlsScanResult
import io.safebyte.tlsinspector.TlsSeverity

/** Outcome of evaluating a single compliance requirement against a scan result. */
sealed class RequirementOutcome {
    data class Pass(val note: String = "") : RequirementOutcome()
    data class Fail(
        val message: String,
        val severity: TlsSeverity = TlsSeverity.MEDIUM,
        val evidence: Map<String, String> = emptyMap()
    ) : RequirementOutcome()
    /** The scan did not gather enough data to assess this requirement. */
    data class NotTestable(val reason: String) : RequirementOutcome()
}

/**
 * A single compliance requirement that can be evaluated against a [TlsScanResult].
 *
 * @param id   Short machine-readable identifier, e.g. "MOZ_INT_NO_TLS10"
 * @param title Human-readable title shown in the report
 * @param spec  Normative reference (e.g. "Mozilla Intermediate §3.1")
 * @param check Function returning [RequirementOutcome] given the accumulated scan data
 */
data class ComplianceRequirement(
    val id: String,
    val title: String,
    val spec: String,
    val check: (TlsScanResult) -> RequirementOutcome
)
