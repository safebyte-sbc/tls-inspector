package io.safebyte.tlsinspector.settings

import burp.api.montoya.MontoyaApi

/**
 * Persistent settings for TLS Inspector.
 *
 * Backed by Burp's per-extension preferences store, so values survive Burp
 * restarts but stay scoped to this extension.
 */
class TlsInspectorSettings(api: MontoyaApi) {

    private val prefs = api.persistence().preferences()

    /** Default port pre-filled in the input row. */
    var tlsDefaultPort: Int
        get() = prefs.getInteger("tls.defaultPort") ?: 443
        set(v) = prefs.setInteger("tls.defaultPort", v)

    /** Default speed budget — must be a `ScanBudget` enum name (FAST/NORMAL/THOROUGH). */
    var tlsScanBudgetDefault: String
        get() = prefs.getString("tls.scanBudgetDefault") ?: "NORMAL"
        set(v) = prefs.setString("tls.scanBudgetDefault", v)

    /** Optional SNI override; blank means use the hostname. */
    var tlsSniOverride: String
        get() = prefs.getString("tls.sniOverride") ?: ""
        set(v) = prefs.setString("tls.sniOverride", v)

    /**
     * Whether probes that perform external lookups (CT logs, OCSP, CRL, CAA DNS,
     * HSTS preload sync) are allowed to talk to the internet. Off by default for
     * air-gapped engagements; users opt in via the input row checkbox.
     */
    var allowExternalQueries: Boolean
        get() = prefs.getBoolean("tls.allowExternalQueries") ?: true
        set(v) = prefs.setBoolean("tls.allowExternalQueries", v)

    /** TLS handshake timeout in ms. */
    var tlsHandshakeTimeoutMs: Int
        get() = prefs.getInteger("tls.handshakeTimeoutMs") ?: 5000
        set(v) = prefs.setInteger("tls.handshakeTimeoutMs", v)
}
