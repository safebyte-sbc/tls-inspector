package io.safebyte.tlsinspector

import com.eclipsesource.json.Json

/**
 * Catalog of well-known weak Diffie-Hellman primes.
 *
 * Entries are loaded lazily from `/tls/weak-dh-primes.json` (bundled in the JAR's
 * resources). Primes are indexed by their SHA-256 hex fingerprint so [HandshakeParser]
 * can identify them in a DHE ServerKeyExchange without comparing full big-integer values.
 *
 * Covered groups:
 *  - RFC 2409 Groups 1 (768-bit) and 2 (1024-bit) — historical IPSec MODP groups,
 *    widely reused by TLS servers in the early 2010s (Logjam / weakdh.org).
 *  - RFC 5114 Groups 22/23 — later MODP groups with small subgroups (Bleichenbacher
 *    small-subgroup attack surface).
 *  - 512-bit DHE_EXPORT prime identified by the Logjam researchers.
 */
object WeakDhPrimes {

    /**
     * A catalog entry for a known weak DH prime.
     *
     * @param label     Human-readable name (e.g. "RFC 2409 Group 2 (well-known IPSec MODP-1024)").
     * @param sizeBits  Bit length of the prime (e.g. 768, 1024, 2048).
     * @param sha256    SHA-256 hex digest of the raw big-endian prime bytes (lowercase, no separator).
     * @param source    Authoritative URL documenting this prime.
     */
    data class Entry(
        val label: String,
        val sizeBits: Int,
        val sha256: String,
        val source: String,
    )

    private val all: List<Entry> by lazy {
        val stream = javaClass.getResourceAsStream("/tls/weak-dh-primes.json")
            ?: error("weak-dh-primes.json not in resources — check the JAR build")
        stream.bufferedReader(Charsets.UTF_8).use { reader ->
            Json.parse(reader).asArray().map { v ->
                val o = v.asObject()
                Entry(
                    label = o.getString("label", ""),
                    sizeBits = o.getInt("sizeBits", 0),
                    sha256 = o.getString("sha256", ""),
                    source = o.getString("source", "")
                )
            }
        }
    }

    private val bySha: Map<String, Entry> by lazy {
        all.associateBy { it.sha256.lowercase() }
    }

    /**
     * Look up a DH prime by its SHA-256 fingerprint.
     *
     * @param sha256Hex Case-insensitive hex string of the SHA-256 digest.
     * @return The matching [Entry], or null if the prime is not in the catalog.
     */
    fun lookup(sha256Hex: String): Entry? = bySha[sha256Hex.lowercase()]

    /** Total number of entries in the catalog (for diagnostics / test assertions). */
    fun count(): Int = all.size
}
