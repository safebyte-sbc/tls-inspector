package io.safebyte.tlsinspector.compliance

/**
 * A named compliance policy (e.g. Mozilla Intermediate, PCI DSS 4.0) composed of
 * a list of [ComplianceRequirement] entries.
 *
 * @param id           Short machine-readable identifier, e.g. "MOZILLA_INTERMEDIATE"
 * @param displayName  Full human-readable name
 * @param version      Policy version string, e.g. "5.7 (2023-08)"
 * @param reference    Canonical URL to the specification
 * @param requirements Ordered list of requirements to evaluate
 */
data class CompliancePolicy(
    val id: String,
    val displayName: String,
    val version: String,
    val reference: String,
    val requirements: List<ComplianceRequirement>
)
