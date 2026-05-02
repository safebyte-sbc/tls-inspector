package io.safebyte.tlsinspector.probes

import io.safebyte.tlsinspector.ProbeContext
import io.safebyte.tlsinspector.TlsScanResult
import io.safebyte.tlsinspector.reporting.TlsFinding

/**
 * Contract for a TLS probe. Implementations must:
 *  - check ctx.cancelled() between long operations
 *  - mutate `result` only via add operations on its mutable maps/lists
 *  - return a list of findings to be merged into result.findings by the runner
 */
interface TlsProbe {
    val id: String
    val displayName: String get() = id
    val kind: ProbeKind

    /** Existing API — backward compatible: probes return findings only.
     *  Prefer `runWithResult()` for new code. */
    fun run(ctx: ProbeContext, result: TlsScanResult): List<TlsFinding>

    /** New API — full ProbeResult with verdict. Default implementation wraps
     *  the legacy `run()` in `ProbeResult.informational(...)` for backward compat.
     *  New probes should override this directly. */
    fun runWithResult(ctx: ProbeContext, result: TlsScanResult): ProbeResult {
        val started = System.currentTimeMillis()
        return try {
            val findings = run(ctx, result)
            ProbeResult.informational(id, displayName, findings, System.currentTimeMillis() - started)
        } catch (e: Exception) {
            ProbeResult.error(id, displayName, e.message ?: e.javaClass.simpleName,
                System.currentTimeMillis() - started)
        }
    }
}
