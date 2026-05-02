package io.safebyte.tlsinspector.certificate

/**
 * RFC 6125 / RFC 9525 hostname verification:
 *   - SAN dNSName takes precedence over CN (CN-only is deprecated since 2017)
 *   - Wildcards may appear ONLY in the leftmost label, and only before a dot
 *   - Wildcard must not match across labels (*.example.com matches a.example.com but not a.b.example.com)
 *   - IP literals must match SAN iPAddress, NEVER CN
 *
 * Returns a structured result so callers can cite the exact reason a match failed.
 */
object HostnameMatcher {

    sealed class MatchResult {
        sealed class Match : MatchResult() {
            object ExactSan : Match()
            object WildcardSan : Match()
            object IpSan : Match()
            object LegacyCommonName : Match()
        }
        data class NoMatch(val reason: String) : MatchResult()
    }

    private val PUBLIC_SUFFIXES_2L = setOf("co.uk", "com.au", "co.jp", "co.za")
    private val SINGLE_LABEL_TLDS = setOf(
        "com", "net", "org", "io", "ro", "uk", "de", "fr", "ca", "us", "info", "biz",
        "edu", "gov", "mil", "int", "eu", "cn", "jp", "au", "ru", "br", "in", "nl"
    )

    fun matches(host: String, cert: ParsedCertificate): MatchResult {
        val target = host.trim().lowercase()
        if (target.isEmpty()) return MatchResult.NoMatch("empty host")

        val isIp = target.matches(Regex("""^[\d.]+$""")) || target.contains(":")
        val dnsSans = cert.subjectAlternativeNames.filter { it.type == SanType.DNS }
        val ipSans = cert.subjectAlternativeNames.filter { it.type == SanType.IP_ADDRESS }

        if (isIp) {
            if (ipSans.any { it.value.equals(target, ignoreCase = true) }) return MatchResult.Match.IpSan
            return MatchResult.NoMatch("no matching IP SAN")
        }

        for (san in dnsSans) {
            val pattern = san.value.lowercase()
            if (pattern == target) return MatchResult.Match.ExactSan
            if (pattern.startsWith("*.") && wildcardMatches(pattern, target)) return MatchResult.Match.WildcardSan
        }

        if (dnsSans.isEmpty()) {
            val cn = cert.subjectDn.commonName?.lowercase()
            if (cn == target) return MatchResult.Match.LegacyCommonName
        }

        return MatchResult.NoMatch(
            "no matching SAN, CN fallback ${if (dnsSans.isEmpty()) "did not match" else "not allowed (DNS SANs present)"}"
        )
    }

    private fun wildcardMatches(pattern: String, target: String): Boolean {
        // Reject TLD wildcards: "*.com", "*.co.uk"
        val rest = pattern.removePrefix("*.")
        if (rest in SINGLE_LABEL_TLDS) return false
        if (rest in PUBLIC_SUFFIXES_2L) return false
        // The wildcard suffix must itself contain at least one dot (e.g. "example.com")
        // to prevent *.example matching example — the rest must be a proper domain
        if (!rest.contains('.')) return false
        // Single-label wildcard: pattern "*.example.com" matches "x.example.com" but not "x.y.example.com"
        if (!target.endsWith(".$rest")) return false
        val labelPart = target.removeSuffix(".$rest")
        return !labelPart.contains(".")
    }

    /**
     * Wildcard scope risk classification for a SAN entry.
     *
     * - NOT_WILDCARD: not a wildcard pattern
     * - DANGEROUS: wildcard at TLD or known public-suffix level (*.com, *.co.uk)
     * - BROAD: single-level wildcard covering a second-level domain (*.example.com)
     * - NARROW: wildcard deeper than second level (*.api.example.com)
     */
    fun classifyWildcardScope(sanValue: String): WildcardScope {
        if (!sanValue.startsWith("*.")) return WildcardScope.NOT_WILDCARD
        val rest = sanValue.removePrefix("*.")
        val labels = rest.split(".")
        return when {
            labels.size <= 1 -> WildcardScope.DANGEROUS         // *.com — TLD wildcard
            rest in PUBLIC_SUFFIXES_2L -> WildcardScope.DANGEROUS // *.co.uk, *.com.au — public suffix
            labels.size == 2 -> WildcardScope.BROAD             // *.example.com
            else -> WildcardScope.NARROW                         // *.api.example.com or deeper
        }
    }

    enum class WildcardScope { NOT_WILDCARD, NARROW, BROAD, DANGEROUS }
}
