package io.safebyte.tlsinspector.probes

import io.safebyte.tlsinspector.reporting.TlsFinding

/**
 * Outcome of a single probe execution. Carries both a Status (how the probe
 * itself ran) and a Verdict (what it concluded about the target).
 */
data class ProbeResult(
    val probeId: String,
    val displayName: String,
    val status: Status,
    val verdict: Verdict,
    val findings: List<TlsFinding>,
    val message: String? = null,
    val durationMs: Long,
) {
    enum class Status { SUCCESS, NOT_APPLICABLE, ERROR, TIMEOUT, SKIPPED }

    companion object {
        fun notVulnerable(id: String, name: String, ms: Long) =
            ProbeResult(id, name, Status.SUCCESS, Verdict.NOT_VULNERABLE, emptyList(), null, ms)

        fun vulnerable(id: String, name: String, findings: List<TlsFinding>, ms: Long, msg: String? = null) =
            ProbeResult(id, name, Status.SUCCESS, Verdict.VULNERABLE, findings, msg, ms)

        fun potentiallyVulnerable(id: String, name: String, findings: List<TlsFinding>, ms: Long, msg: String? = null) =
            ProbeResult(id, name, Status.SUCCESS, Verdict.POTENTIALLY_VULNERABLE, findings, msg, ms)

        fun notApplicable(id: String, name: String, reason: String, ms: Long) =
            ProbeResult(id, name, Status.NOT_APPLICABLE, Verdict.NOT_APPLICABLE, emptyList(), reason, ms)

        fun informational(id: String, name: String, findings: List<TlsFinding>, ms: Long) =
            ProbeResult(id, name, Status.SUCCESS, Verdict.UNDETERMINED, findings, null, ms)

        fun error(id: String, name: String, msg: String, ms: Long) =
            ProbeResult(id, name, Status.ERROR, Verdict.UNDETERMINED, emptyList(), msg, ms)

        fun timeout(id: String, name: String, ms: Long) =
            ProbeResult(id, name, Status.TIMEOUT, Verdict.UNDETERMINED, emptyList(), "timed out", ms)
    }
}

enum class Verdict(val displayName: String, val isFinding: Boolean) {
    VULNERABLE("Vulnerable", true),
    POTENTIALLY_VULNERABLE("Potentially vulnerable", true),
    NOT_VULNERABLE("Not vulnerable", false),
    NOT_APPLICABLE("Not applicable", false),
    UNDETERMINED("—", false),
}

enum class ProbeKind {
    /** Pass/fail probe (Heartbleed, POODLE, FREAK). UI shows verdict. */
    VULNERABILITY,
    /** Informational probe (protocol/cipher enum, cert validation). */
    INFORMATIONAL,
}
