package org.osservatorionessuno.libmvt.android.parsers

import org.osservatorionessuno.libmvt.android.analyzer.APKStaticAnalyzer
import org.osservatorionessuno.libmvt.common.logging.LogUtils
import java.io.ByteArrayInputStream
import java.io.File
import java.io.InputStream
import java.util.zip.ZipInputStream

// https://github.com/TheZ3ro/androguard-legacy/blob/master/androguard/core/bytecodes/apk.py
object APKParser {
    data class APKInfo(
        val packageName: String,
        val versionCode: String,
        val versionName: String,
        val files: List<String>,
        val certificates: List<CertificateParser.CertificateInfo>,
        /** Whether the APK signature verified. False means [certificates] are unauthenticated. */
        val verified: Boolean,
        val suspicious: Boolean,
    )

    @JvmStatic
    fun extractFileName(filePath: String): String {
        val marker = "==/"
        if (filePath.contains(marker)) {
            val parts = filePath.split(marker)
            if (parts.size > 1) {
                return "_" + parts[1].replace(".apk", "")
            }
        }
        return ""
    }

    /**
     * Parse an APK from a file. This is usually called for on-device APK before dumping them. (Bugbane)
     */
    @JvmStatic
    fun parseAPK(apk: File): APKInfo {
        LogUtils.d("APKParser", "Parsing APK: ${apk.name}")
        // Signature and entries are both read as a stream: an APK can outgrow the heap.
        return parseAPKEntries(SignatureParser().parseAPKSignature(apk), apk.inputStream().buffered())
    }

    /**
     * Parse an APK from a stream. This is used when analyzing an acquisition from ZIP file. (libmvt)
     */
    @JvmStatic
    fun parseAPK(input: InputStream): APKInfo {
        LogUtils.d("APKParser", "Parsing APK from stream")
        // apksig needs random access, so this path has to buffer the whole APK.
        val apkBytes = input.readBytes()
        return parseAPKEntries(
            SignatureParser().parseAPKSignature(apkBytes),
            ByteArrayInputStream(apkBytes),
        )
    }

    private fun parseAPKEntries(
        signatureInfo: SignatureParser.APKSignatureInfo,
        apkStream: InputStream,
    ): APKInfo {
        // A repackaged APK keeps the original signer certificate but breaks its signature, so
        // skipping analysis on the fingerprint alone would hide exactly the tampering we look for.
        val trustedCertificates =
            if (signatureInfo.verified) {
                signatureInfo.signerCertificates.filter { it.trusted }
            } else {
                // Debug, not warn: i/w land on stdout and would corrupt the CLI's JSON output.
                LogUtils.d("APKParser", "APK signature did not verify, no certificate is trusted")
                emptyList()
            }

        // Get the manifest information from the APK
        val files = mutableListOf<String>()
        var binaryManifest: ByteArray? = null
        ZipInputStream(apkStream).use { zip ->
            var entry = zip.nextEntry
            while (entry != null) {
                if (!entry.isDirectory) {
                    val name = entry.name
                    if (isTrackedApkEntry(name)) {
                        files.add(name)
                    }
                    if (name == "AndroidManifest.xml") {
                        binaryManifest = zip.readBytes()
                    }
                }
                zip.closeEntry()
                entry = zip.nextEntry
            }
        }

        val manifestBytes = binaryManifest
            ?: throw IllegalArgumentException("AndroidManifest.xml not found in APK")
        val manifestInfo = ManifestParser().parseManifest(ByteArrayInputStream(manifestBytes), false)

        var suspicious = false
        // If the APK has no trusted certificates, we need to analyze it statically
        if (trustedCertificates.isEmpty()) {
            LogUtils.d("APKParser", "No trusted certificates found, analyzing APK statically")
            // Small static analysis euristic to determine if the APK is suspicious
            suspicious = APKStaticAnalyzer.analyze(manifestInfo.manifest)
        }

        // Return the APK info
        return APKInfo(
            packageName = manifestInfo.packageName,
            versionCode = manifestInfo.versionCode,
            versionName = manifestInfo.versionName,
            files = files,
            certificates = signatureInfo.signerCertificates,
            verified = signatureInfo.verified,
            suspicious = suspicious,
        )
    }

    private fun isTrackedApkEntry(name: String): Boolean =
        name.startsWith("assets/")
            || name.startsWith("res/raw/")
            || name.startsWith("res/xml/")
            || name.startsWith("lib/")
}
