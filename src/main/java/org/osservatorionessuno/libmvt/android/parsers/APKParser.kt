package org.osservatorionessuno.libmvt.android.parsers

import org.osservatorionessuno.libmvt.common.logging.LogUtils
import org.osservatorionessuno.libmvt.android.parsers.SignatureParser
import org.osservatorionessuno.libmvt.android.parsers.ManifestParser
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
    )

    @JvmStatic
    fun parseAPK(apk: File): APKInfo {
        LogUtils.i("APKParser", "Parsing APK: ${apk.name}")

        // Get a list of all files in the APK
        var zipFile = ZipFile(apk)
        var files = mutableListOf<String>()
        zipFile.stream().forEach { entry ->
            files.add(entry.name)
        }

        // Get the signature information from the APK
        var signatureInfo = SignatureParser().parseAPKSignature(apk)
        // TODO: add euristic to ignore known good APKs (??)

        // Get the manifest information from the APK
        var manifest = zipFile.getInputStream(zipFile.getEntry("AndroidManifest.xml"))
        var manifestInfo = ManifestParser().parseManifest(manifest, false)

        // Get the android resources information from the APK
        //var resourcesInfo = ResourceTableParser().parse(zipFile.getInputStream(zipFile.getEntry("resources.arsc")))
        // TODO

        // Return the APK info
        return APKInfo(
            packageName = manifestInfo.packageName,
            versionCode = manifestInfo.versionCode,
            versionName = manifestInfo.versionName,
            files = files,
            certificates = signatureInfo.signerCertificates,
        )
    }
}
