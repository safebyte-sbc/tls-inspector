package io.safebyte.tlsinspector

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import burp.api.montoya.extension.ExtensionUnloadingHandler
import io.safebyte.tlsinspector.menu.TlsContextMenuProvider
import io.safebyte.tlsinspector.settings.TlsInspectorSettings
import io.safebyte.tlsinspector.ui.TlsAuditTab
import javax.swing.SwingUtilities

/**
 * Burp extension entry point.
 *
 * Registers a single top-level "TLS Inspector" tab plus a context menu
 * shortcut. Everything else (probes, runner, reporting) is encapsulated
 * inside the tab and torn down on extension unload.
 */
class TlsInspectorExtension : BurpExtension {

    private lateinit var tab: TlsAuditTab

    override fun initialize(api: MontoyaApi) {
        api.extension().setName("TLS Inspector")

        val settings = TlsInspectorSettings(api)

        // The tab owns the runner, the issue builder, and all UI state.
        // Build it on the EDT — Swing components must not be touched
        // from arbitrary threads.
        SwingUtilities.invokeAndWait {
            tab = TlsAuditTab(api, settings)
            api.userInterface().registerSuiteTab("TLS Inspector", tab.component)
        }

        api.userInterface().registerContextMenuItemsProvider(
            TlsContextMenuProvider(api, tab)
        )

        api.extension().registerUnloadingHandler(ExtensionUnloadingHandler {
            // Cancel any in-flight scan and shut down the worker pool so we
            // don't leak threads when the user reloads or removes the extension.
            runCatching { tab.shutdown() }
        })

        api.logging().logToOutput("TLS Inspector ${BuildInfo.VERSION} loaded.")
    }
}

private object BuildInfo {
    const val VERSION = "1.0.0"
}
