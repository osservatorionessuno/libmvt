package org.osservatorionessuno.libmvt.android.parsers

import org.osservatorionessuno.libmvt.common.logging.LogUtils
import org.osservatorionessuno.libmvt.android.parsers.SignatureParser
import org.osservatorionessuno.libmvt.android.parsers.ManifestParser
import org.osservatorionessuno.libmvt.android.analyzer.APKStaticAnalyzer
import java.io.File
import java.io.InputStream
import java.util.zip.ZipFile

// https://github.com/TheZ3ro/androguard-legacy/blob/master/androguard/core/bytecodes/apk.py
object APKParser {
    data class APKInfo(
        val packageName: String,
        val versionCode: String,
        val versionName: String,
        val files: List<String>,
        val certificates: List<CertificateParser.CertificateInfo>,
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

    @JvmStatic
    fun parseAPK(apk: File): APKInfo {
        LogUtils.i("APKParser", "Parsing APK: ${apk.name}")

        // Get a list of all files in the APK
        var zipFile = ZipFile(apk)
        var files = mutableListOf<String>()
        zipFile.stream().forEach { entry ->
            if (entry.name.startsWith("assets/") 
            || entry.name.startsWith("res/raw/") 
            || entry.name.startsWith("res/xml/") 
            || entry.name.startsWith("lib/")) {
                files.add(entry.name)
            }
        }

        // Get the signature information from the APK
        var signatureInfo = SignatureParser().parseAPKSignature(apk)
        // TODO: add euristic to ignore known good APKs (??)

        // Get the manifest information from the APK
        var binaryManifest = zipFile.getInputStream(zipFile.getEntry("AndroidManifest.xml"))
        var manifestInfo = ManifestParser().parseManifest(binaryManifest, false)

        // Small static analysis euristic to determine if the APK is suspicious
        var suspicious = APKStaticAnalyzer.analyze(manifestInfo.manifest)

        // Return the APK info
        return APKInfo(
            packageName = manifestInfo.packageName,
            versionCode = manifestInfo.versionCode,
            versionName = manifestInfo.versionName,
            files = files,
            certificates = signatureInfo.signerCertificates,
            suspicious = suspicious,
        )
    }
}
