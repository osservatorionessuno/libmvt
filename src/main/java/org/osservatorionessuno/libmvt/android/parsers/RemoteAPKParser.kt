package org.osservatorionessuno.libmvt.android.parsers

import org.osservatorionessuno.libmvt.android.analyzer.APKStaticAnalyzer
import org.osservatorionessuno.libmvt.common.Utils
import org.osservatorionessuno.libmvt.common.logging.LogUtils
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * When in Analyst mode, Bugbane uses a remote adb shell to interact with the device.
 * APKParser class relies on APK files being available for a `open()` call.
 * However we cannot do that remotely and we don't want to pull all the APKs to analyze them.
 *
 * Since we don't want to drop an agent on the device, we use a couple of shell commands.
 *
 * Limits vs local [APKParser]:
 * - [APKParser.APKInfo.verified] is always false (should we trust Android service call?).
 * - Therefore allowlist [CertificateParser.CertificateInfo.trusted] stays false.
 * - Transaction code for `getPackageInfo` is probed and cached per process.
 */
object RemoteAPKParser {
    private const val TAG = "RemoteAPKParser"

    /** [android.content.pm.PackageManager.GET_SIGNATURES] | GET_SIGNING_CERTIFICATES as decimal. */
    private const val SIGNING_FLAGS = 64 or 0x08000000

    /** Probe range for IPackageManager.getPackageInfo ordinal (varies by API/OEM). */
    private val PACKAGE_INFO_CODES = 2..12

    /** Cached working `service call package` transaction code, or -1 if probe failed. */
    @Volatile
    private var packageInfoCode: Int = 0

    /**
     * Clears the probed `getPackageInfo` ordinal so tests start from a clean slate.
     * This is only used by tests and should not be used in production.
     * @see RemoteAPKParserParcelTest
     */
    @JvmStatic
    fun resetCachedServiceCallCode() {
        packageInfoCode = 0
    }

    /**
     * Minimal shell surface so this parser stays free of bugbane/cadb.
     * [org.osservatorionessuno.cadb.AdbShell] satisfies this in Analyst mode.
     */
    interface Shell {
        fun execForEachLine(command: String, onLine: (String) -> Unit)
        fun execToStream(command: String, output: OutputStream)
    }

    data class PmDumpInfo(
        val versionName: String = "",
        val versionCode: String = "",
        val requestedPermissions: List<String> = emptyList(),
    )

    /**
     * Parse a remote APK at [apkPath] for [packageName] via shell commands on [shell].
     */
    @JvmStatic
    fun parse(shell: Shell, packageName: String, apkPath: String): APKParser.APKInfo {
        val files = listTrackedEntries(shell, apkPath)
        val certificates = certificatesViaServiceCall(shell, packageName)
        val pm = fetchPmDump(shell, packageName)
        
        var packageNameOut = packageName
        var versionCode = pm.versionCode
        var versionName = pm.versionName
        var suspicious = false

        val manifestBytes = extractManifest(shell, apkPath)
        if (manifestBytes != null) {
            runCatching {
                val info = ManifestParser().parseManifest(ByteArrayInputStream(manifestBytes), false)
                if (info.packageName.isNotBlank()) packageNameOut = info.packageName
                if (info.versionCode.isNotBlank()) versionCode = info.versionCode
                if (info.versionName.isNotBlank()) versionName = info.versionName

                // can we trust the service call from Android?
                // for now we will assume cert are not trusted so we will always run the static heuristic.
                suspicious = APKStaticAnalyzer.analyze(info.manifest)
            }.onFailure { LogUtils.w(TAG, "Manifest parse failed for $apkPath: ${it.message}") }
        } else if (pm.requestedPermissions.isNotEmpty()) {
            // Oh dear, we couldn't get the manifest from the APK by unzipping.
            // No problemo, we will use `pm dump` output to check for suspicious permissions.
            suspicious = APKStaticAnalyzer.permissionsLookSuspicious(pm.requestedPermissions)
        }

        return APKParser.APKInfo(
            packageName = packageNameOut,
            versionCode = versionCode,
            versionName = versionName,
            files = files,
            certificates = certificates,
            verified = false,
            suspicious = suspicious,
        )
    }

    /** `unzip -l` name column, filtered like [Utils.isTrackedApkEntry]. */
    @JvmStatic
    fun parseUnzipList(output: String): List<String> =
        output.lineSequence()
            .map { it.trim() }
            .mapNotNull { line ->
                if (line.isEmpty() || line.startsWith("Archive:") || line.startsWith("Length") ||
                    line.startsWith("--------") || line.startsWith("---------")
                ) {
                    return@mapNotNull null
                }
                val name = line.substringAfterLast(' ').trim()
                // Trailing summary is "N files".
                if (name.isEmpty() || name == "Name" || name == "files") return@mapNotNull null
                name.takeIf { Utils.isTrackedApkEntry(it) }
            }
            .toList()

    /**
     * Scan Parcel bytes for X.509 certs. At each ASN.1 SEQUENCE start (`0x30`), let
     * [CertificateFactory] parse — no hand-rolled DER length decoding.
     * Dedupes by SHA-256 of the encoded cert.
     */
    @JvmStatic
    fun certificatesFromParcelBytes(parcel: ByteArray): List<CertificateParser.CertificateInfo> {
        val factory = CertificateFactory.getInstance("X.509")
        val seen = HashSet<String>()
        val result = ArrayList<CertificateParser.CertificateInfo>()
        var i = 0
        while (i < parcel.size) {
            if (parcel[i] != 0x30.toByte()) {
                i++
                continue
            }
            val stream = ByteArrayInputStream(parcel, i, parcel.size - i)
            val cert = runCatching {
                factory.generateCertificate(stream) as X509Certificate
            }.getOrNull()
            if (cert == null) {
                i++
                continue
            }
            val der = cert.encoded
            if (seen.add(Utils.sha256Hex(der))) {
                // PM-attested only — never claim apksig verification.
                result.add(CertificateParser.fromX509Certificate(cert, false))
            }
            // Skip what the factory consumed (junk after a false 0x30 advances by 1 above).
            i += (parcel.size - i) - stream.available()
        }
        return result
    }

    @JvmStatic
    fun parsePmDumpOutput(output: String): PmDumpInfo {
        var versionName = ""
        var versionCode = ""
        val requested = ArrayList<String>()
        var inRequested = false
        for (raw in output.lineSequence()) {
            val line = raw.trimEnd()
            val trimmed = line.trim()
            if (inRequested) {
                // requested permissions are indented with 6 spaces in dumpsys/pm dump
                if (!line.startsWith("      ") || trimmed.isEmpty()) {
                    inRequested = false
                } else {
                    requested.add(trimmed)
                    continue
                }
            }
            when {
                trimmed.startsWith("versionName=") ->
                    versionName = trimmed.removePrefix("versionName=").trim()
                trimmed.startsWith("versionCode=") ->
                    // "versionCode=9 minSdk=30 targetSdk=36" — keep the leading int token
                    versionCode = trimmed.removePrefix("versionCode=").trim()
                        .substringBefore(' ').trim()
                trimmed == "requested permissions:" -> inRequested = true
            }
        }
        return PmDumpInfo(versionName, versionCode, requested)
    }

    private fun listTrackedEntries(shell: Shell, apkPath: String): List<String> {
        val quoted = Utils.shQuote(apkPath)
        return runCatching {
            val sb = StringBuilder()
            shell.execForEachLine("unzip -l $quoted") { sb.appendLine(it) }
            parseUnzipList(sb.toString())
        }.onFailure { LogUtils.w(TAG, "unzip -l failed for $apkPath: ${it.message}") }
            .getOrDefault(emptyList())
    }

    private fun extractManifest(shell: Shell, apkPath: String): ByteArray? {
        val quoted = Utils.shQuote(apkPath)
        return runCatching {
            val buf = ByteArrayOutputStream()
            shell.execToStream("unzip -p $quoted AndroidManifest.xml", buf)
            buf.toByteArray().takeIf { it.isNotEmpty() }
        }.onFailure { LogUtils.w(TAG, "unzip -p AndroidManifest.xml failed for $apkPath: ${it.message}") }
            .getOrNull()
    }

    private fun fetchPmDump(shell: Shell, packageName: String): PmDumpInfo {
        val quoted = Utils.shQuote(packageName)
        return runCatching {
            val sb = StringBuilder()
            shell.execForEachLine("pm dump $quoted") { sb.appendLine(it) }
            parsePmDumpOutput(sb.toString())
        }.onFailure { LogUtils.w(TAG, "pm dump failed for $packageName: ${it.message}") }
            .getOrDefault(PmDumpInfo())
    }

    private fun certificatesViaServiceCall(
        shell: Shell,
        packageName: String,
    ): List<CertificateParser.CertificateInfo> {
        val code = resolvePackageInfoCode(shell, packageName) ?: return emptyList()
        return runCatching {
            val out = StringBuilder()
            shell.execForEachLine(serviceCallCmd(code, packageName)) { out.appendLine(it) }
            certificatesFromParcelBytes(Utils.parcelBytesFromServiceCallOutput(out.toString()))
        }.onFailure { LogUtils.w(TAG, "service call cert extract failed for $packageName: ${it.message}") }
            .getOrDefault(emptyList())
    }

    private fun resolvePackageInfoCode(shell: Shell, packageName: String): Int? {
        val cached = packageInfoCode
        if (cached > 0) return cached
        if (cached < 0) return null

        for (code in PACKAGE_INFO_CODES) {
            val certs = runCatching {
                val out = StringBuilder()
                shell.execForEachLine(serviceCallCmd(code, packageName)) { out.appendLine(it) }
                val text = out.toString()
                if (!text.contains("Parcel(")) return@runCatching emptyList()
                val parcel = Utils.parcelBytesFromServiceCallOutput(text)
                // Prefer a parcel that mentions the package (ASCII column or UTF-8 body).
                if (!text.contains(packageName) &&
                    !parcel.toString(Charsets.ISO_8859_1).contains(packageName)
                ) {
                    return@runCatching emptyList()
                }
                certificatesFromParcelBytes(parcel)
            }.getOrDefault(emptyList())
            if (certs.isNotEmpty()) {
                packageInfoCode = code
                return code
            }
        }
        packageInfoCode = -1
        LogUtils.w(TAG, "No working getPackageInfo service-call code in $PACKAGE_INFO_CODES")
        return null
    }

    private fun serviceCallCmd(code: Int, packageName: String): String =
        "service call package $code s16 ${Utils.shQuote(packageName)} i32 $SIGNING_FLAGS i32 0"
}
