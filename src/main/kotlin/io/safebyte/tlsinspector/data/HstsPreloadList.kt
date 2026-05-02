package io.safebyte.tlsinspector.data

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue

/**
 * Bundled HSTS preload list loader.
 *
 * **Gap (to be resolved in MS E):** This bundled subset contains ~75 well-known entries.
 * The full Chromium preload list has ~150K entries and is updated several times per week.
 * Full list deferred to MS E where it will be fetched and cached at startup time from
 * https://www.chromium.org/hsts/preload-list/hstspreload.h or the JSON API at
 * https://hstspreload.org/api/v2/entries.
 *
 * Resource file: `tls/hsts-preload.json` (bundled in the JAR under resources/).
 */
object HstsPreloadList {

    @JsonIgnoreProperties(ignoreUnknown = true)
    private data class HstsEntry(
        @JsonProperty("name") val name: String,
        @JsonProperty("include_subdomains") val includeSubdomains: Boolean = false
    )

    @JsonIgnoreProperties(ignoreUnknown = true)
    private data class HstsPreloadRoot(
        @JsonProperty("entries") val entries: List<HstsEntry> = emptyList()
    )

    private val mapper = jacksonObjectMapper()

    /** Map from domain → include_subdomains flag. Loaded once at first access. */
    val entries: Map<String, Boolean> by lazy {
        try {
            val resource = HstsPreloadList::class.java.classLoader
                .getResourceAsStream("tls/hsts-preload.json")
                ?: error("tls/hsts-preload.json not found in classpath")
            val root: HstsPreloadRoot = resource.use { mapper.readValue(it) }
            root.entries.associate { it.name to it.includeSubdomains }
        } catch (e: Exception) {
            emptyMap()
        }
    }

    /**
     * Check if [domain] is in the preload list.
     *
     * @param domain The hostname to check (e.g. "api.github.com" or "github.com").
     * @return [PreloadStatus.InList] if the domain itself or a parent with include_subdomains=true
     *         is in the list; [PreloadStatus.NotInList] otherwise. Note that a [PreloadStatus.NotInList]
     *         result is inconclusive for the bundled subset — check [PreloadStatus.BundledSubsetOnly].
     */
    fun check(domain: String): PreloadStatus {
        // Exact match
        entries[domain]?.let { return PreloadStatus.InList(domain, it) }

        // Parent domain wildcard match (include_subdomains = true)
        val parts = domain.split('.')
        for (i in 1 until parts.size - 1) {
            val parent = parts.subList(i, parts.size).joinToString(".")
            val includeSubdomains = entries[parent]
            if (includeSubdomains == true) return PreloadStatus.InList(parent, true)
        }

        return PreloadStatus.NotInList(bundledSubsetOnly = true)
    }

    val size: Int get() = entries.size
}

sealed class PreloadStatus {
    /** Domain (or parent) found in the preload list. */
    data class InList(val matchedDomain: String, val includeSubdomains: Boolean) : PreloadStatus()

    /**
     * Domain not found in the bundled preload list.
     * @param bundledSubsetOnly When true, the result is inconclusive — the full Chromium list
     *                          may contain this domain. Use only for known-high-value domains.
     */
    data class NotInList(val bundledSubsetOnly: Boolean) : PreloadStatus()
}
