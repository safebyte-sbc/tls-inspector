package io.safebyte.tlsinspector.compliance

import io.safebyte.tlsinspector.TlsScanResult

/**
 * Evaluates a [CompliancePolicy] against a [TlsScanResult] and produces a [PolicyEvaluation].
 */
object ProfileEvaluator {

    fun evaluate(policy: CompliancePolicy, result: TlsScanResult): PolicyEvaluation {
        val requirementResults = policy.requirements.map { req ->
            val outcome = try {
                req.check(result)
            } catch (e: Exception) {
                RequirementOutcome.NotTestable("Evaluation error: ${e.message}")
            }
            RequirementResult(req, outcome)
        }
        return PolicyEvaluation(policy, requirementResults)
    }
}
