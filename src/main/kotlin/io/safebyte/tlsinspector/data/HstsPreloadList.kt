package io.safebyte.tlsinspector.data

import com.eclipsesource.json.Json

/**
 * Bundled HSTS preload list loader.
 *
 * **Gap:** This bundled subset contains ~75 well-known entries.
 * The full Chromium preload list has ~150K entries and is updated several times per week.
 * Future work: fetch and cache the full list at startup from
 * https://www.chromium.org/hsts/preload-list/hstspreload.h or the JSON API at
 * https://hstspreload.org/api/v2/entries.
 *
 * Resource file: `tls/hsts-preload.json` (bundled in the JAR under resources/).
 */
object HstsPreloadList {

    /** Map from domain → include_subdomains flag. Loaded once at first access. */
    val entries: Map<String, Boolean> by lazy {
        try {
            val resource = HstsPreloadList::class.java.classLoader
                .getResourceAsStream("tls/hsts-preload.json")
                ?: error("tls/hsts-preload.json not found in classpath")
            resource.bufferedReader(Charsets.UTF_8).use { reader ->
                val root = Json.parse(reader).asObject()
                val list = root.get("entries")?.asArray() ?: return@use emptyMap<String, Boolean>()
                list.associate { v ->
                    val o = v.asObject()
                    o.getString("name", "") to (o.getBoolean("include_subdomains", false))
                }
            }
        } catch (e: Exception) {
            emptyMap()
        }
    }

    /**
     * Check if [domain] is in the preload list.
     *
     * @return [PreloadStatus.InList] if the domain itself or a parent with include_subdomains=true
     *         is in the list; [PreloadStatus.NotInList] otherwise. Note that a [PreloadStatus.NotInList]
     *         result is inconclusive for the bundled subset — check [PreloadStatus.NotInList.bundledSubsetOnly].
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
