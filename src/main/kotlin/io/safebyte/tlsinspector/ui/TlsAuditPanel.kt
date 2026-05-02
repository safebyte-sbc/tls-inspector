package io.safebyte.tlsinspector.ui

import io.safebyte.tlsinspector.ScanBudget
import io.safebyte.tlsinspector.ScanProfile
import io.safebyte.tlsinspector.settings.TlsInspectorSettings
import java.awt.FlowLayout
import javax.swing.*

/**
 * Input controls panel for the TLS Audit Scanner.
 * All controls on a single compact horizontal row:
 * Host | Port | SNI | Speed | Compliance | Run | Cancel | Clear
 *
 * "Speed" controls scan timing/aggressiveness (ScanBudget: FAST/NORMAL/THOROUGH).
 * "Compliance" picks the baseline against which the server's TLS config is graded
 * (ScanProfile: Mozilla 3 tiers / PCI / NIST / Banking EU / All).
 */
class TlsAuditPanel(
    private val onRun: (host: String, port: Int, budget: ScanBudget, profile: ScanProfile) -> Unit,
    private val onCancel: () -> Unit,
    private val onClear: () -> Unit,
    private val onSaveHtml: () -> Unit,
    private val settings: TlsInspectorSettings
) {

    private val hostField = JTextField(20)
    private val portSpinner = JSpinner(SpinnerNumberModel(
        settings.tlsDefaultPort.coerceIn(1, 65535), 1, 65535, 1
    )).apply {
        // Keep port spinner compact
        preferredSize = java.awt.Dimension(70, preferredSize.height)
    }
    private val speedCombo: JComboBox<ScanBudget> = JComboBox(ScanBudget.values()).apply {
        selectedItem = runCatching { ScanBudget.valueOf(settings.tlsScanBudgetDefault) }
            .getOrDefault(ScanBudget.NORMAL)
        toolTipText = "FAST = short timeouts (3s), NORMAL = balanced (5s), THOROUGH = patient (10s, 2 concurrent)"
    }
    private val complianceCombo: JComboBox<ScanProfile> = JComboBox(ScanProfile.values()).apply {
        selectedItem = ScanProfile.MOZILLA_INTERMEDIATE
        toolTipText = "Compliance baseline used to grade the server's TLS configuration"
        // Show displayName instead of enum name
        renderer = object : DefaultListCellRenderer() {
            override fun getListCellRendererComponent(
                list: JList<*>?, value: Any?, index: Int, isSelected: Boolean, cellHasFocus: Boolean
            ): java.awt.Component {
                val text = (value as? ScanProfile)?.displayName ?: value?.toString() ?: ""
                return super.getListCellRendererComponent(list, text, index, isSelected, cellHasFocus)
            }
        }
    }
    private val sniField = JTextField(15).apply {
        text = settings.tlsSniOverride.ifBlank { "" }
        toolTipText = "Leave blank to use the hostname as SNI"
    }

    private val runButton = JButton("Run Scan")
    private val cancelButton = JButton("Cancel").apply { isEnabled = false }
    private val clearButton = JButton("Clear")
    private val saveButton = JButton("Save HTML").apply { isEnabled = false }

    /** The root panel exposed to TlsAuditTab. */
    val component: JPanel = buildPanel()

    init {
        runButton.addActionListener {
            val host = hostField.text.trim()
            if (host.isEmpty()) {
                JOptionPane.showMessageDialog(
                    component, "Host cannot be empty.", "Input Error", JOptionPane.WARNING_MESSAGE
                )
                return@addActionListener
            }
            val port = portSpinner.value as Int
            val budget = speedCombo.selectedItem as ScanBudget
            val profile = complianceCombo.selectedItem as ScanProfile
            onRun(host, port, budget, profile)
        }
        cancelButton.addActionListener { onCancel() }
        clearButton.addActionListener { onClear() }
        saveButton.addActionListener { onSaveHtml() }
    }

    private fun buildPanel(): JPanel {
        val panel = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))
        panel.border = BorderFactory.createTitledBorder("TLS Audit Scanner")

        panel.add(JLabel("Host:"))
        panel.add(hostField)

        panel.add(JLabel("Port:"))
        panel.add(portSpinner)

        panel.add(JLabel("SNI:"))
        panel.add(sniField)

        panel.add(JLabel("Speed:"))
        panel.add(speedCombo)

        panel.add(JLabel("Compliance:"))
        panel.add(complianceCombo)

        panel.add(runButton)
        panel.add(cancelButton)
        panel.add(clearButton)
        panel.add(saveButton)

        return panel
    }

    /** Allow the tab to enable Save HTML once a scan completes (or there is content worth saving). */
    fun setSaveEnabled(enabled: Boolean) {
        saveButton.isEnabled = enabled
    }

    /**
     * Pre-fill host + port from a context-menu "Send to TLS Audit Scanner" action.
     * Must be called on the EDT.
     */
    fun setTarget(host: String, port: Int) {
        hostField.text = host
        portSpinner.value = port.coerceIn(1, 65535)
    }

    /**
     * Enable or disable all input controls while a scan is running.
     */
    fun setEnabled(enabled: Boolean) {
        hostField.isEnabled = enabled
        portSpinner.isEnabled = enabled
        speedCombo.isEnabled = enabled
        complianceCombo.isEnabled = enabled
        sniField.isEnabled = enabled
        runButton.isEnabled = enabled
        cancelButton.isEnabled = !enabled   // Cancel active while scan runs
        clearButton.isEnabled = enabled
        // While a scan runs, disable Save (avoid saving partial HTML); when scan ends,
        // re-enable so the user can export the final report.
        saveButton.isEnabled = enabled
    }
}
