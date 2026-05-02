package io.safebyte.tlsinspector

import org.bouncycastle.tls.CipherSuite
import java.lang.reflect.Modifier

object TlsConfig {
    const val MAX_HISTORY = 10
    const val MAX_CIPHERS_PER_PROTOCOL = 100
    const val MAX_CHAIN_LENGTH = 10

    const val PROBE_PROTOCOL_ENUM = "PROTOCOL_ENUM"
    const val PROBE_CIPHER_ENUM = "CIPHER_ENUM"
    const val PROBE_CERT_VALIDATION = "CERT_VALIDATION"

    /** TLS 1.3 + ECDHE-AEAD ciphers — modern probe baseline. */
    val DEFAULT_CIPHER_SUITES_MODERN: IntArray = intArrayOf(
        CipherSuite.TLS_AES_256_GCM_SHA384,
        CipherSuite.TLS_AES_128_GCM_SHA256,
        CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    )

    /**
     * Full set of cipher suite constants declared in CipherSuite class, enumerated via
     * reflection. Used for cipher suite enumeration probes.
     */
    val ALL_CIPHER_SUITES: IntArray by lazy {
        val fields = CipherSuite::class.java.declaredFields
            .filter { Modifier.isStatic(it.modifiers) && it.type == Int::class.javaPrimitiveType }
        fields.map { it.getInt(null) }.distinct().toIntArray()
    }

    /**
     * Reverse mapping from cipher suite int value to IANA name.
     * Used because CipherSuite in BCTLS 1.79 has no getName() static method.
     */
    val CIPHER_SUITE_NAMES: Map<Int, String> by lazy {
        val fields = CipherSuite::class.java.declaredFields
            .filter { Modifier.isStatic(it.modifiers) && it.type == Int::class.javaPrimitiveType }
        fields.associate { it.getInt(null) to it.name }
    }

    fun getCipherSuiteName(id: Int): String = CIPHER_SUITE_NAMES[id] ?: "UNKNOWN_0x${id.toString(16).padStart(4, '0')}"
}
