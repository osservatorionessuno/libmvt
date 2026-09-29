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
 * - [Session] caches the `getPackageInfo` transaction code for one acquisition.
 */
object RemoteAPKParser {
    private const val TAG = "RemoteAPKParser"

    /** [android.content.pm.PackageManager.GET_SIGNATURES] | GET_SIGNING_CERTIFICATES as decimal. */
    private const val SIGNING_FLAGS = 64 or 0x08000000

    /** Probe range for IPackageManager.getPackageInfo ordinal (varies by API/OEM). */
    private val PACKAGE_INFO_CODES = 2..12

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
     * Parse a single remote APK. Use [Session] to reuse discovery across an acquisition.
     */
    @JvmStatic
    fun parse(shell: Shell, packageName: String, apkPath: String): APKParser.APKInfo =
        Session(shell).parse(packageName, apkPath)

    /**
     * Reuse for all APKs in one acquisition; create a new session when changing targets.
     * Only successful discovery is cached. A missing package or failed shell call can be
     * retried by the next parse without discarding a code already known to work on this target.
     */
    class Session(private val shell: Shell) {
        private var packageInfoCode: Int? = null

        fun parse(packageName: String, apkPath: String): APKParser.APKInfo {
            val files = listTrackedEntries(shell, apkPath)
            val certificates = certificatesViaServiceCall(packageName)
            val pm = fetchPmDump(shell, packageName)

            val info = extractManifest(shell, apkPath)?.let { bytes ->
                runCatching { ManifestParser().parseManifest(ByteArrayInputStream(bytes), false) }
                    .onFailure { LogUtils.w(TAG, "Manifest parse failed for $apkPath: ${it.message}") }
                    .getOrNull()
            }

            // Certs are PM-attested only, so always run the static heuristic. Without a usable
            // manifest fall back to the `pm dump` permission list.
            val suspicious = if (info != null) {
                APKStaticAnalyzer.analyze(info.manifest)
            } else {
                APKStaticAnalyzer.permissionsLookSuspicious(pm.requestedPermissions)
            }

            return APKParser.APKInfo(
                packageName = info?.packageName?.ifBlank { null } ?: packageName,
                versionCode = info?.versionCode?.ifBlank { null } ?: pm.versionCode,
                versionName = info?.versionName?.ifBlank { null } ?: pm.versionName,
                files = files,
                certificates = certificates,
                verified = false,
                suspicious = suspicious,
            )
        }

        private fun certificatesViaServiceCall(
            packageName: String,
        ): List<CertificateParser.CertificateInfo> {
            val codes = packageInfoCode?.let { it..it } ?: PACKAGE_INFO_CODES
            for (code in codes) {
                val certs = runCatching {
                    val out = StringBuilder()
                    shell.execForEachLine(serviceCallCmd(code, packageName)) { out.appendLine(it) }
                    certificatesFromParcelBytes(Utils.parcelBytesFromServiceCallOutput(out.toString()))
                }.getOrDefault(emptyList())
                if (certs.isNotEmpty()) {
                    packageInfoCode = code
                    return certs
                }
            }
            LogUtils.w(TAG, "No signer certificates from service-call codes $codes for $packageName")
            return emptyList()
        }

    }

    /**
     * `flags` is `int` before API 33 and `long` after. `i32 FLAGS i32 0` works on both: old
     * reads (flags, userId=0); new reads the two words as one long and userId past the end as 0.
     */
    private fun serviceCallCmd(code: Int, packageName: String): String =
        "service call package $code s16 ${Utils.shQuote(packageName)} i32 $SIGNING_FLAGS i32 0"

    /** `unzip -l` name column, filtered like [Utils.isTrackedApkEntry]. */
    @JvmStatic
    fun parseUnzipList(output: String): List<String> =
        output.lineSequence()
            .mapNotNull { UNZIP_LIST_LINE.matchEntire(it)?.groupValues?.get(1) }
            .filter(Utils::isTrackedApkEntry)
            .toList()

    /** `  Length  Date  Time  Name`; name may contain spaces. Header/footer rows don't match. */
    private val UNZIP_LIST_LINE = Regex("""^\s*\d+\s+\S+\s+\S+\s+(.+?)\s*$""")

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
            // PM-attested only — never claim apksig verification.
            val info = CertificateParser.fromX509Certificate(cert, false)
            if (seen.add(info.checksums.sha256)) result.add(info)
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
        var packageBlocks = 0
        for (raw in output.lineSequence()) {
            val line = raw.trimEnd()
            val trimmed = line.trim()
            // Only the first block: updated system apps repeat under "Hidden system packages:".
            if (trimmed.startsWith("Package [") && ++packageBlocks > 1) break
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
}
