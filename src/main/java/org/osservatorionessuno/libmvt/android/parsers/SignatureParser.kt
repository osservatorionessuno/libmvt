package org.osservatorionessuno.libmvt.android.parsers

import com.android.apksig.ApkVerifier
import com.android.apksig.apk.ApkFormatException
import com.android.apksig.util.DataSources
import java.io.File
import java.nio.ByteBuffer
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
        return parseSignature(ApkVerifier.Builder(apk).build())
    }

    /**
     * Same as [parseAPKSignature] but verifies an APK already loaded in memory.
     */
    @Throws(SignatureParsingException::class)
    fun parseAPKSignature(apkBytes: ByteArray): APKSignatureInfo {
        val dataSource = DataSources.asDataSource(ByteBuffer.wrap(apkBytes))
        return parseSignature(ApkVerifier.Builder(dataSource).build())
    }

    @Throws(SignatureParsingException::class)
    private fun parseSignature(verifier: ApkVerifier): APKSignatureInfo {
        val result =
            try {
                verifier.verify()
            } catch (e: ApkFormatException) {
                throw SignatureParsingException("Failed to verify APK: ${e.message}", e)
            }

        // apksig fills signerCertificates only once an APK verifies, so a certificate found by
        // walking the per-scheme signers below usually comes from an APK that failed to verify.
        // Those certificates are still reported, but they cannot be trusted: pass the verdict
        // down so the allowlist is only consulted for a signature that actually checked out.
        val verified = result.isVerified

        val certs =
            if (result.signerCertificates.isNotEmpty()) {
                // apksig only returns verified certificates.
                result.signerCertificates.map { CertificateParser.fromX509Certificate(it, verified) }
            } else {
                val collected = mutableListOf<CertificateParser.CertificateInfo>()
                fun addFromCert(cert: X509Certificate?) {
                    // we hardcode a false, preventing edge-cases where apksig returns verified
                    // but we end up manually loading unverified certificates.
                    cert?.let { collected.add(CertificateParser.fromX509Certificate(it, false)) }
                }
                result.v4SchemeSigners.forEach { addFromCert(it.certificate) }
                result.v31SchemeSigners.forEach { addFromCert(it.certificate) }
                result.v3SchemeSigners.forEach { addFromCert(it.certificate) }
                result.v2SchemeSigners.forEach { addFromCert(it.certificate) }
                result.v1SchemeSigners.forEach { addFromCert(it.certificate) }
                LogUtils.d(
                    "SignatureParser",
                    "Found ${collected.size} certificates after manual search",
                )
                if (collected.isEmpty()) {
                    throw SignatureParsingException("No certificates found after manual search")
                }
                collected
            }

        return APKSignatureInfo(
            verified = verified,
            signerCertificates = certs,
            verifiedUsingV1Scheme = result.isVerifiedUsingV1Scheme,
            verifiedUsingV2Scheme = result.isVerifiedUsingV2Scheme,
            verifiedUsingV3Scheme = result.isVerifiedUsingV3Scheme,
            verifiedUsingV31Scheme = result.isVerifiedUsingV31Scheme,
            verifiedUsingV4Scheme = result.isVerifiedUsingV4Scheme,
        )
    }
}