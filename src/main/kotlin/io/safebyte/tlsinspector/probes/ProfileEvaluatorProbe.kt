package io.safebyte.tlsinspector.probes

import io.safebyte.tlsinspector.ProbeContext
import io.safebyte.tlsinspector.ScanProfile
import io.safebyte.tlsinspector.TlsConfidence
import io.safebyte.tlsinspector.TlsScanResult
import io.safebyte.tlsinspector.TlsSeverity
import io.safebyte.tlsinspector.compliance.CompliancePolicy
import io.safebyte.tlsinspector.compliance.EnisaBankingProfile
import io.safebyte.tlsinspector.compliance.MozillaProfile
import io.safebyte.tlsinspector.compliance.Nist80052r2Profile
import io.safebyte.tlsinspector.compliance.PciDss40Profile
import io.safebyte.tlsinspector.compliance.ProfileEvaluator
import io.safebyte.tlsinspector.compliance.RequirementOutcome
import io.safebyte.tlsinspector.reporting.TlsFinding

/**
 * Profile Evaluator Probe — runs LAST after all data collection probes.
 *
 * Evaluates the scan result against the compliance policies configured in [ctx.profile].
 * Emits:
 *   - One [TlsFinding] per failing requirement (severity = requirement's severity)
 *   - One summary [TlsFinding] per evaluated policy (INFO, always emitted)
 *
 * The probe always runs INFORMATIONAL (kind = INFORMATIONAL) since compliance evaluation
 * is a reporting output, not an exploitability verdict.
 */
class ProfileEvaluatorProbe : TlsProbe {
    override val id = "PROFILE_EVALUATOR"
    override val displayName = "Compliance Profile Evaluator"
    override val kind = ProbeKind.INFORMATIONAL

    override fun run(ctx: ProbeContext, result: TlsScanResult): List<TlsFinding> =
        runWithResult(ctx, result).findings

    override fun runWithResult(ctx: ProbeContext, result: TlsScanResult): ProbeResult {
        val started = System.currentTimeMillis()

        val policies = policiesForProfile(ctx.profile)
        val findings = mutableListOf<TlsFinding>()

        for (policy in policies) {
            val evaluation = ProfileEvaluator.evaluate(policy, result)

            // Emit one finding per failing requirement
            for (reqResult in evaluation.requirementResults) {
                val outcome = reqResult.outcome
                if (outcome is RequirementOutcome.Fail) {
                    val finding = TlsFinding(
                        id = "PROFILE_EVALUATOR:${policy.id}:${reqResult.requirement.id}",
                        title = "[${policy.displayName}] ${reqResult.requirement.title}",
                        severity = outcome.severity,
                        confidence = TlsConfidence.FIRM,
                        descriptionHtml = """
                            <p><b>Compliance requirement:</b> ${reqResult.requirement.title}</p>
                            <p><b>Specification:</b> ${reqResult.requirement.spec}</p>
                            <p><b>Failure reason:</b> ${outcome.message}</p>
                            ${if (outcome.evidence.isNotEmpty())
                                "<p><b>Evidence:</b><br>${outcome.evidence.entries.joinToString("<br>") { "${it.key}: ${it.value}" }}</p>"
                            else ""}
                            <p><b>Policy:</b> ${policy.displayName} (${policy.version})</p>
                        """.trimIndent(),
                        references = listOf(policy.reference),
                        evidence = outcome.evidence
                    )
                    synchronized(result) { result.findings.add(finding) }
                    findings.add(finding)
                }
            }

            // Summary finding per policy (INFO, always)
            val summaryTitle = if (evaluation.isCompliant) {
                "[${policy.displayName}] Compliant — ${evaluation.passCount} checks passed"
            } else {
                "[${policy.displayName}] Non-Compliant — ${evaluation.failCount} check(s) failed"
            }
            val summaryItems = evaluation.requirementResults.joinToString("") { reqResult ->
                val (icon, note) = when (reqResult.outcome) {
                    is RequirementOutcome.Pass -> "&#x2705;" to ""
                    is RequirementOutcome.Fail -> "&#x274C;" to " &mdash; ${(reqResult.outcome as RequirementOutcome.Fail).message.take(80)}"
                    is RequirementOutcome.NotTestable -> "&#x2753;" to " (${(reqResult.outcome as RequirementOutcome.NotTestable).reason.take(60)})"
                }
                "<li>$icon <b>${reqResult.requirement.id}</b>: ${reqResult.requirement.title}$note</li>"
            }

            val summary = TlsFinding(
                id = "PROFILE_EVALUATOR:${policy.id}:summary",
                title = summaryTitle,
                severity = if (evaluation.isCompliant) TlsSeverity.INFO else evaluation.worstSeverity,
                confidence = TlsConfidence.FIRM,
                descriptionHtml = """
                    <p><b>Policy:</b> ${policy.displayName} (${policy.version})</p>
                    <p><b>Result:</b> ${if (evaluation.isCompliant) "COMPLIANT" else "NON-COMPLIANT"} &mdash;
                    ${evaluation.passCount} passed, ${evaluation.failCount} failed,
                    ${evaluation.naCount} not testable</p>
                    <ul>
                    $summaryItems
                    </ul>
                """.trimIndent(),
                references = listOf(policy.reference)
            )
            synchronized(result) { result.findings.add(summary) }
            findings.add(summary)
        }

        return ProbeResult.informational(id, displayName, findings, System.currentTimeMillis() - started)
    }

    /**
     * Map a [ScanProfile] to the list of [CompliancePolicy] entries to evaluate.
     * [ScanProfile.ALL] evaluates against every published baseline (6 policies).
     */
    private fun policiesForProfile(profile: ScanProfile): List<CompliancePolicy> = when (profile) {
        ScanProfile.MOZILLA_OLD          -> listOf(MozillaProfile.OLD)
        ScanProfile.MOZILLA_INTERMEDIATE -> listOf(MozillaProfile.INTERMEDIATE)
        ScanProfile.MOZILLA_MODERN       -> listOf(MozillaProfile.MODERN)
        ScanProfile.PCI_DSS_4            -> listOf(PciDss40Profile.POLICY)
        ScanProfile.NIST_800_52R2        -> listOf(Nist80052r2Profile.POLICY)
        ScanProfile.BANKING_EU           -> listOf(EnisaBankingProfile.POLICY)
        ScanProfile.ALL                  -> listOf(
            MozillaProfile.OLD,
            MozillaProfile.INTERMEDIATE,
            MozillaProfile.MODERN,
            PciDss40Profile.POLICY,
            Nist80052r2Profile.POLICY,
            EnisaBankingProfile.POLICY,
        )
    }
}
