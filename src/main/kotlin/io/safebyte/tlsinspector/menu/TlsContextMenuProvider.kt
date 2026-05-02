package io.safebyte.tlsinspector.menu

import burp.api.montoya.MontoyaApi
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider
import io.safebyte.tlsinspector.ui.TlsAuditTab
import javax.swing.JMenuItem

class TlsContextMenuProvider(
    private val api: MontoyaApi,
    private val tab: TlsAuditTab
) : ContextMenuItemsProvider {

    override fun provideMenuItems(event: ContextMenuEvent): MutableList<java.awt.Component> {
        val items = mutableListOf<java.awt.Component>()
        val target = extractTarget(event) ?: return items
        items.add(JMenuItem("Send to TLS Inspector").apply {
            addActionListener {
                tab.prefillTarget(target.first, target.second)
                api.logging().logToOutput("[TLS Inspector] Pre-filled ${target.first}:${target.second} from context menu.")
            }
        })
        return items
    }

    private fun extractTarget(event: ContextMenuEvent): Pair<String, Int>? {
        event.messageEditorRequestResponse().orElse(null)?.let {
            val s = it.requestResponse().httpService(); return s.host() to s.port()
        }
        val sel = event.selectedRequestResponses()
        if (sel.isNotEmpty()) { val s = sel.first().httpService(); return s.host() to s.port() }
        return null
    }
}
