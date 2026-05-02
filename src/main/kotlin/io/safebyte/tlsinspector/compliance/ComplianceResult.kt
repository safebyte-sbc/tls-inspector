package io.safebyte.tlsinspector.compliance

import io.safebyte.tlsinspector.TlsSeverity

/**
 * Aggregated result of evaluating a [CompliancePolicy] against a scan result.
 */
data class PolicyEvaluation(
    val policy: CompliancePolicy,
    val requirementResults: List<RequirementResult>,
) {
    val passCount: Int   get() = requirementResults.count { it.outcome is RequirementOutcome.Pass }
    val failCount: Int   get() = requirementResults.count { it.outcome is RequirementOutcome.Fail }
    val naCount: Int     get() = requirementResults.count { it.outcome is RequirementOutcome.NotTestable }
    val isCompliant: Boolean get() = failCount == 0

    /** Highest severity among failing requirements, or INFO if all pass. */
    val worstSeverity: TlsSeverity
        get() = requirementResults
            .mapNotNull { (it.outcome as? RequirementOutcome.Fail)?.severity }
            .maxByOrNull { it.ordinal }
            ?: TlsSeverity.INFO
}

data class RequirementResult(
    val requirement: ComplianceRequirement,
    val outcome: RequirementOutcome
)
