package org.osservatorionessuno.libmvt.android.parsers

import com.android.apksig.ApkVerifier
import com.android.apksig.apk.ApkFormatException
import java.io.File
import java.security.cert.X509Certificate
import org.osservatorionessuno.libmvt.common.logging.LogUtils

class SignatureParser {
    data class APKSignatureInfo(
        val verified: Boolean,
        val signerCertificates: List<CertificateParser.CertificateInfo>,
        val verifiedUsingV1Scheme: Boolean,
        val verifiedUsingV2Scheme: Boolean,
        val verifiedUsingV3Scheme: Boolean,
        val verifiedUsingV31Scheme: Boolean,
        val verifiedUsingV4Scheme: Boolean,
    )

    class SignatureParsingException(message: String, cause: Throwable? = null) : Exception(message, cause)

    /**
     * Extracts the signature from the APK using Android's apksig library.
     *
     * Returns information about the validity of the signature and the certificates used.
     */
    @Throws(SignatureParsingException::class)
    fun parseAPKSignature(apk: File): APKSignatureInfo {
        val verifier = ApkVerifier.Builder(apk).build()
        val result =
            try {
                verifier.verify()
            } catch (e: ApkFormatException) {
                throw SignatureParsingException("Failed to verify APK: ${e.message}", e)
            }

        val certs =
            if (result.signerCertificates.isNotEmpty()) {
                result.signerCertificates.map { CertificateParser.fromX509Certificate(it) }
            } else {
                // apksig has a bug where it can verify an APK but leave signerCertificates empty.
                val collected = mutableListOf<CertificateParser.CertificateInfo>()
                fun addFromCert(cert: X509Certificate?) {
                    cert?.let { collected.add(CertificateParser.fromX509Certificate(it)) }
                }
                result.v4SchemeSigners.forEach { addFromCert(it.certificate) }
                result.v31SchemeSigners.forEach { addFromCert(it.certificate) }
                result.v3SchemeSigners.forEach { addFromCert(it.certificate) }
                result.v2SchemeSigners.forEach { addFromCert(it.certificate) }
                result.v1SchemeSigners.forEach { addFromCert(it.certificate) }
                LogUtils.w(
                    "SignatureParser",
                    "Found ${collected.size} certificates after manual search",
                )
                if (collected.isEmpty()) {
                    throw SignatureParsingException("No certificates found after manual search")
                }
                collected
            }

        return APKSignatureInfo(
            verified = result.isVerified,
            signerCertificates = certs,
            verifiedUsingV1Scheme = result.isVerifiedUsingV1Scheme,
            verifiedUsingV2Scheme = result.isVerifiedUsingV2Scheme,
            verifiedUsingV3Scheme = result.isVerifiedUsingV3Scheme,
            verifiedUsingV31Scheme = result.isVerifiedUsingV31Scheme,
            verifiedUsingV4Scheme = result.isVerifiedUsingV4Scheme,
        )
    }
}