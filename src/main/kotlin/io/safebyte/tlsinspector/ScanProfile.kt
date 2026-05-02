package io.safebyte.tlsinspector

/**
 * Compliance baseline used by ProfileEvaluatorProbe to grade the scanned
 * server's TLS configuration. The user picks one (or ALL) from the UI's
 * "Compliance" dropdown.
 *
 * Distinct from ScanBudget which controls scan SPEED (FAST/NORMAL/THOROUGH).
 */
enum class ScanProfile(val displayName: String) {
    MOZILLA_OLD("Mozilla SSL — Old (legacy compat)"),
    MOZILLA_INTERMEDIATE("Mozilla SSL — Intermediate (default)"),
    MOZILLA_MODERN("Mozilla SSL — Modern (TLS 1.3 only)"),
    PCI_DSS_4("PCI DSS 4.0 §4.2.1"),
    NIST_800_52R2("NIST SP 800-52r2"),
    BANKING_EU("Banking EU (ENISA + ETSI TS 119 312)"),
    /** Evaluate against all of the above and emit findings per baseline. */
    ALL("All profiles (Mozilla 3 tiers + PCI + NIST + Banking EU)"),
}
