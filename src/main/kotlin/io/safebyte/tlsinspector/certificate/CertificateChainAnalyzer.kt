package io.safebyte.tlsinspector.certificate

import java.io.ByteArrayInputStream
import java.security.KeyStore
import java.security.cert.CertPathValidator
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.X509Certificate

data class ChainAnalysis(
    val isValid: Boolean,
    val trustedRoot: ParsedCertificate?,
    val validationErrors: List<String>,
    val missingIntermediate: Boolean
)

object CertificateChainAnalyzer {

    fun analyze(chain: List<ParsedCertificate>, trustStore: KeyStore? = null): ChainAnalysis {
        if (chain.isEmpty()) return ChainAnalysis(false, null, listOf("empty chain"), false)

        val errors = mutableListOf<String>()
        val ks = trustStore ?: runCatching { defaultTrustStore() }.getOrElse {
            errors.add("Could not load trust store: ${it.message}")
            return ChainAnalysis(false, null, errors, chain.size == 1 && !chain[0].isSelfSigned)
        }
        val cf = CertificateFactory.getInstance("X.509")
        val x509Chain = chain.map { cf.generateCertificate(ByteArrayInputStream(it.derEncoded)) as X509Certificate }
        val certPath = cf.generateCertPath(x509Chain)

        val trustedRoot: ParsedCertificate? = try {
            val params = PKIXParameters(ks).apply { isRevocationEnabled = false }
            val validator = CertPathValidator.getInstance("PKIX")
            val res = validator.validate(certPath, params)
            // Map trust anchor to ParsedCertificate if possible
            val anchor = (res as? java.security.cert.PKIXCertPathValidatorResult)?.trustAnchor?.trustedCert
            anchor?.let { runCatching { CertificateInspector.parse(it.encoded) }.getOrNull() }
        } catch (e: Exception) {
            errors.add(e.message ?: e.javaClass.simpleName)
            null
        }

        val isValid = errors.isEmpty()
        val missingIntermediate = chain.size == 1 && !chain[0].isSelfSigned
        return ChainAnalysis(isValid, trustedRoot, errors, missingIntermediate)
    }

    private fun defaultTrustStore(): KeyStore {
        val ks = KeyStore.getInstance(KeyStore.getDefaultType())
        val tsFile = System.getProperty("javax.net.ssl.trustStore")
            ?: "${System.getProperty("java.home")}/lib/security/cacerts"
        val tsPassword = System.getProperty("javax.net.ssl.trustStorePassword") ?: "changeit"
        java.io.FileInputStream(tsFile).use { ks.load(it, tsPassword.toCharArray()) }
        return ks
    }
}
