package io.safebyte.tlsinspector.ui

import burp.api.montoya.MontoyaApi
import io.safebyte.tlsinspector.ScanBudget
import io.safebyte.tlsinspector.ScanProfile
import io.safebyte.tlsinspector.TlsScanHandle
import io.safebyte.tlsinspector.TlsScanRunner
import io.safebyte.tlsinspector.reporting.TlsIssueBuilder
import io.safebyte.tlsinspector.settings.TlsInspectorSettings
import java.awt.BorderLayout
import java.io.File
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.text.SimpleDateFormat
import java.util.Date
import javax.swing.JFileChooser
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.SwingUtilities
import javax.swing.filechooser.FileNameExtensionFilter

class TlsAuditTab(api: MontoyaApi, settings: TlsInspectorSettings) {

    private val runner = TlsScanRunner(api)
    private val issueBuilder = TlsIssueBuilder(api)
    private val inputPanel = TlsAuditPanel(::onRun, ::onCancel, ::onClear, ::onSaveHtml, settings)
    private val htmlPanel = TlsResultsHtmlPanel(issueBuilder)

    @Volatile private var lastHost: String = ""
    @Volatile private var lastPort: Int = 0

    val component: JPanel = JPanel(BorderLayout(8, 8)).apply {
        add(inputPanel.component, BorderLayout.NORTH)
        add(htmlPanel.component, BorderLayout.CENTER)
    }

    @Volatile private var currentHandle: TlsScanHandle? = null

    fun prefillTarget(host: String, port: Int) =
        SwingUtilities.invokeLater { inputPanel.setTarget(host, port) }

    private fun onRun(host: String, port: Int, budget: ScanBudget, profile: ScanProfile) {
        // Guard: block if a scan is running (finishedAt == null means still in progress).
        val prev = currentHandle
        if (prev != null && synchronized(prev.result) { prev.result.finishedAt } == null) return

        lastHost = host
        lastPort = port
        inputPanel.setEnabled(false)
        htmlPanel.setHeader(host, port, "${budget.name} / ${profile.displayName}")

        val probeNames = listOf(
            "PROTOCOL_ENUM" to "Protocol Version Enumeration",
            "CIPHER_ENUM" to "Cipher Suite Enumeration",
            "CERT_VALIDATION" to "Certificate Validation",
            "HEARTBLEED" to "Heartbleed (CVE-2014-0160)",
            "POODLE_SSLV3" to "POODLE on SSLv3 (CVE-2014-3566)",
            "FREAK" to "FREAK (CVE-2015-0204)",
            "SWEET32" to "Sweet32 (CVE-2016-2183)",
            "DROWN" to "DROWN (CVE-2016-0800)",
            "BEAST" to "BEAST (CVE-2011-3389)",
            "LUCKY13" to "Lucky13 (CVE-2013-0169)",
            "CRIME" to "CRIME (CVE-2012-4929)",
            "CCS_INJECTION" to "CCS Injection (CVE-2014-0224)",
            "FALLBACK_SCSV" to "TLS_FALLBACK_SCSV Honored",
            "LOGJAM_EXPORT" to "Logjam Export (DHE_EXPORT)",
            "LOGJAM_COMMON_PRIME" to "Logjam (Common 1024-bit DH Prime)",
            "ROBOT" to "ROBOT (CVE-2017-13099)",
            "RACCOON" to "Raccoon DHE Key Reuse (CVE-2020-1968)",
            "ALPACA" to "ALPACA Cross-Protocol Confusion (CVE-2021-3618)",
            "ZERO_RTT_REPLAY" to "TLS 1.3 0-RTT Replay Risk",
            "HRR_ABUSE" to "TLS 1.3 HRR Binding Regression",
            // MS D
            "OCSP_REVOCATION" to "OCSP Revocation Check",
            "CRL_REVOCATION" to "CRL Revocation Check",
            "OCSP_STAPLING" to "OCSP Stapling (RFC 6066)",
            "CT_LOG" to "Certificate Transparency Log (crt.sh)",
            "CAA_DNS" to "CAA DNS Record Check (RFC 8659)",
            "HSTS_PRELOAD" to "HSTS Header + Preload Check (RFC 6797)",
            "PROFILE_EVALUATOR" to "Compliance Profile Evaluator",
            // MS E
            "PQC_KEM" to "Post-Quantum Hybrid KEM Support",
        )
        htmlPanel.registerProbes(probeNames)

        val handle = runner.start(host, port, sniOverride = null, budget = budget, profile = profile)
        currentHandle = handle

        Thread({
            val seen = mutableSetOf<String>()
            // Poll until the scan thread marks finishedAt (set in the runner's finally block).
            while (synchronized(handle.result) { handle.result.finishedAt } == null) {
                val snapshot = synchronized(handle.result) { handle.result.probeResults.toList() }
                for (pr in snapshot) {
                    if (pr.probeId !in seen) {
                        seen.add(pr.probeId)
                        htmlPanel.updateProbe(pr)
                    }
                }
                Thread.sleep(200)
            }
            // Final flush after scan completes
            val final = synchronized(handle.result) { handle.result.probeResults.toList() }
            for (pr in final) {
                if (pr.probeId !in seen) {
                    seen.add(pr.probeId)
                    htmlPanel.updateProbe(pr)
                }
            }
            SwingUtilities.invokeLater {
                htmlPanel.renderFinalResult(handle.result, host, port)
                inputPanel.setEnabled(true)
            }
        }, "tls-tab-await").apply { isDaemon = true }.start()
    }

    private fun onCancel() { currentHandle?.cancel() }
    private fun onClear() {
        htmlPanel.reset()
        inputPanel.setSaveEnabled(false)
    }

    private fun onSaveHtml() {
        val html = htmlPanel.getHtml()
        if (html.isBlank()) {
            JOptionPane.showMessageDialog(
                component,
                "No scan results to save yet.",
                "Save HTML",
                JOptionPane.INFORMATION_MESSAGE
            )
            return
        }

        val safeHost = lastHost.ifBlank { "tls-audit" }.replace(Regex("[^A-Za-z0-9._-]"), "_")
        val portPart = if (lastPort > 0) "-$lastPort" else ""
        val ts = SimpleDateFormat("yyyyMMdd-HHmmss").format(Date())
        val defaultName = "tls-audit-${safeHost}${portPart}-${ts}.html"

        val chooser = JFileChooser().apply {
            dialogTitle = "Save TLS Audit Report"
            fileFilter = FileNameExtensionFilter("HTML files (*.html, *.htm)", "html", "htm")
            selectedFile = File(defaultName)
        }
        if (chooser.showSaveDialog(component) != JFileChooser.APPROVE_OPTION) return

        var target = chooser.selectedFile
        if (!target.name.lowercase().let { it.endsWith(".html") || it.endsWith(".htm") }) {
            target = File(target.parentFile, target.name + ".html")
        }
        if (target.exists()) {
            val overwrite = JOptionPane.showConfirmDialog(
                component,
                "File '${target.name}' already exists. Overwrite?",
                "Confirm Overwrite",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE
            )
            if (overwrite != JOptionPane.YES_OPTION) return
        }

        try {
            Files.write(target.toPath(), html.toByteArray(StandardCharsets.UTF_8))
            JOptionPane.showMessageDialog(
                component,
                "Saved to:\n${target.absolutePath}",
                "Save HTML",
                JOptionPane.INFORMATION_MESSAGE
            )
        } catch (ex: Exception) {
            JOptionPane.showMessageDialog(
                component,
                "Failed to save file:\n${ex.message}",
                "Save HTML — Error",
                JOptionPane.ERROR_MESSAGE
            )
        }
    }

    fun shutdown() {
        currentHandle?.cancel()
        runner.shutdown()
    }
}
