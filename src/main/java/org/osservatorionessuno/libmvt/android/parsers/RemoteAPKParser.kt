package org.osservatorionessuno.libmvt.android.parsers

import org.osservatorionessuno.libmvt.android.analyzer.APKStaticAnalyzer
import org.osservatorionessuno.libmvt.common.Utils
import org.osservatorionessuno.libmvt.common.logging.LogUtils
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.OutputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.zip.GZIPInputStream

/**
 * When in Analyst mode, Bugbane uses a remote adb shell to interact with the device.
 * APKParser class relies on APK files being available for a `open()` call.
 * However we cannot do that remotely and we don't want to pull all the APKs to analyze them.
 *
 * Since we don't want to drop an agent on the device, we use a couple of shell commands.
 *
 * Limits vs local [APKParser]:
 * - Certificates come from PackageManager's install record, i.e. the framework's own apksig run
 *   at install time, so [APKParser.APKInfo.verified] is true whenever it returned any. Only a
 *   root-level attacker can forge that record, and one that can also owns `adb pull`.
 * - [Session] caches the `getPackageInfo` transaction code for one acquisition, and
 *   [Session.prefetch] fetches a whole batch of APKs with one command.
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
     *
     * Throw [IOException] when a command cannot run: that step degrades and parsing goes on.
     * Anything else, a user cancel for instance, propagates out of [Session.parse] untouched.
     */
    interface Shell {
        fun execForEachLine(command: String, onLine: (String) -> Unit)
        fun execToStream(command: String, output: OutputStream)
    }

    /** One APK of a [Session.prefetch] batch; [userId] as in [Session.parse]. */
    data class Apk(val packageName: String, val apkPath: String, val userId: Int = 0)

    data class PmDumpInfo(
        val versionName: String = "",
        val versionCode: String = "",
        val requestedPermissions: List<String> = emptyList(),
    )

    /**
     * Parse a single remote APK. Use [Session] to reuse discovery across an acquisition.
     */
    @JvmStatic
    @JvmOverloads
    fun parse(shell: Shell, packageName: String, apkPath: String, userId: Int = 0): APKParser.APKInfo =
        Session(shell).parse(packageName, apkPath, userId)

    /**
     * Reuse for all APKs in one acquisition; create a new session when changing targets.
     * Only successful discovery is cached. A missing package or failed shell call can be
     * retried by the next parse without discarding a code already known to work on this target.
     */
    class Session(private val shell: Shell) {
        private var packageInfoCode: Int? = null

        // Split APKs parse the same package several times in a row: answer from the first.
        private val certificateCache = HashMap<Pair<String, Int>, List<CertificateParser.CertificateInfo>>()
        private val pmDumpCache = HashMap<String, PmDumpInfo>()

        /**
         * `IPackageManager.getPackageInfo(String, flags, int userId)` takes `int flags` before API 33
         * and `long flags` after, so the `service call` argument width must match or `userId` is
         * misread. Unknown SDK defaults to `i64`, which is right on API 33+ and, for user 0, on older
         * releases too (the high word doubles as userId=0).
         */
        private val flagsType: String by lazy {
            val sdk = shellOr(0, "getprop failed") {
                var v = 0
                shell.execForEachLine("getprop ro.build.version.sdk") { v = it.trim().toIntOrNull() ?: v }
                v
            }
            if (sdk in 1..32) "i32" else "i64"
        }

        // Filled by prefetch, consumed by the next parse of that path: holds one batch at most.
        private val entriesCache = HashMap<String, List<String>>()
        private val manifestCache = HashMap<String, ByteArray>()

        /**
         * Fetch file lists, signer certificates and manifests for [apks] with one gzipped shell
         * command. [parse] then answers from the session; anything the command did not deliver
         * is fetched per APK.
         */
        fun prefetch(apks: List<Apk>) {
            if (apks.isEmpty()) return
            // The getPackageInfo ordinal is probed on the first package the slow way.
            if (packageInfoCode == null) apks.first().let { first ->
                certificatesViaServiceCall(first.packageName, first.userId)
                    .also { if (it.isNotEmpty()) certificateCache[first.packageName to first.userId] = it }
            }
            val code = packageInfoCode
            val certPending = HashSet<Pair<String, Int>>()
            val calls = apks.mapIndexed { i, apk ->
                val wantCert = code != null && (apk.packageName to apk.userId) !in certificateCache &&
                    certPending.add(apk.packageName to apk.userId)
                "a $i ${Utils.shQuote(apk.apkPath)} ${if (wantCert) Utils.shQuote(apk.packageName) else "''"} ${apk.userId}"
            }
            val cert = if (code == null) "" else
                "[ -n \"\$3\" ] && { printf '==CERT==\\n'; service call package $code s16 \"\$3\" $flagsType $SIGNING_FLAGS i32 \"\$4\"; }; "
            // Only tracked entries leave the device; stderr stays out of the gzip stream.
            val script = "a(){ printf '==APK %s==\\n==LIST==\\n' \"\$1\"; unzip -l \"\$2\" | grep -E ' (assets|lib|res/raw|res/xml)/'; " +
                cert + "printf '==MANIFEST==\\n'; unzip -p \"\$2\" AndroidManifest.xml | base64; printf '\\n==END==\\n'; }; " +
                "{ ${calls.joinToString("; ")}; } 2>/dev/null | gzip"
            val compressed = ByteArrayOutputStream()
            shellOr(Unit, "APK batch failed") { shell.execToStream(script, compressed) }
            ingest(apks, compressed.toByteArray())
        }

        /** Caches every APK whose sections arrived whole; a truncated stream stops at the cut. */
        private fun ingest(apks: List<Apk>, compressed: ByteArray) {
            var apk: Apk? = null
            var section: StringBuilder? = null
            val list = StringBuilder()
            val cert = StringBuilder()
            val manifest = StringBuilder()
            var certSeen = false
            // Inflate first: a Reader over a cut stream drops the lines it already decoded.
            val text = ByteArrayOutputStream()
            try {
                GZIPInputStream(ByteArrayInputStream(compressed)).copyTo(text)
            } catch (e: IOException) {
                LogUtils.w(TAG, "APK batch output ended early: ${e.message}")
            }
            for (line in String(text.toByteArray(), Charsets.UTF_8).lineSequence()) when {
                line.startsWith("==APK ") -> {
                    apk = apks.getOrNull(line.removePrefix("==APK ").removeSuffix("==").toIntOrNull() ?: -1)
                    for (b in arrayOf(list, cert, manifest)) b.setLength(0)
                    certSeen = false
                    section = null
                }
                line == "==LIST==" -> section = list
                line == "==CERT==" -> { section = cert; certSeen = true }
                line == "==MANIFEST==" -> section = manifest
                line == "==END==" -> {
                    apk?.let { done ->
                        entriesCache[done.apkPath] = parseUnzipList(list.toString())
                        manifestCache[done.apkPath] = runCatching { Base64.getMimeDecoder().decode(manifest.toString()) }
                            .getOrDefault(ByteArray(0))
                        if (certSeen) {
                            certificatesFromParcelBytes(Utils.parcelBytesFromServiceCallOutput(cert.toString()))
                                .takeIf { it.isNotEmpty() }
                                ?.let { certificateCache[done.packageName to done.userId] = it }
                        }
                    }
                    apk = null
                    section = null
                }
                else -> section?.appendLine(line)
            }
        }

        /** [userId] is the Android user the package is installed for (0 = owner, 10+ = profiles). */
        fun parse(packageName: String, apkPath: String, userId: Int = 0): APKParser.APKInfo {
            val files = entriesCache.remove(apkPath) ?: listTrackedEntries(shell, apkPath)
            val certificates = certificateCache[packageName to userId]
                ?: certificatesViaServiceCall(packageName, userId)
                    .also { if (it.isNotEmpty()) certificateCache[packageName to userId] = it }
            // Fetched only when the manifest is missing or incomplete.
            val pm by lazy {
                pmDumpCache[packageName]
                    ?: fetchPmDump(shell, packageName)?.also { pmDumpCache[packageName] = it }
                    ?: PmDumpInfo()
            }

            val manifestBytes = if (apkPath in manifestCache) manifestCache.remove(apkPath)?.takeIf { it.isNotEmpty() }
                else extractManifest(shell, apkPath)
            val info = manifestBytes?.let { bytes ->
                runCatching { ManifestParser().parseManifest(ByteArrayInputStream(bytes), false) }
                    .onFailure { LogUtils.w(TAG, "Manifest parse failed for $apkPath: ${it.message}") }
                    .getOrNull()
            }

            // Same gate as the local path: a verified, allowlisted signer skips the heuristic.
            // Without a usable manifest fall back to the `pm dump` permission list.
            val suspicious = when {
                certificates.any { it.trusted } -> false
                info != null -> APKStaticAnalyzer.analyze(info.manifest)
                else -> APKStaticAnalyzer.permissionsLookSuspicious(pm.requestedPermissions)
            }

            return APKParser.APKInfo(
                packageName = info?.packageName?.ifBlank { null } ?: packageName,
                versionCode = info?.versionCode?.ifBlank { null } ?: pm.versionCode,
                versionName = info?.versionName?.ifBlank { null } ?: pm.versionName,
                files = files,
                certificates = certificates,
                verified = certificates.isNotEmpty(),
                suspicious = suspicious,
            )
        }

        private fun certificatesViaServiceCall(
            packageName: String,
            userId: Int,
        ): List<CertificateParser.CertificateInfo> {
            val codes = packageInfoCode?.let { it..it } ?: PACKAGE_INFO_CODES
            for (code in codes) {
                val certs = shellOr(emptyList(), "service call $code failed for $packageName") {
                    val out = StringBuilder()
                    shell.execForEachLine(serviceCallCmd(code, packageName, userId)) { out.appendLine(it) }
                    certificatesFromParcelBytes(Utils.parcelBytesFromServiceCallOutput(out.toString()))
                }
                if (certs.isNotEmpty()) {
                    packageInfoCode = code
                    return certs
                }
            }
            LogUtils.w(TAG, "No signer certificates from service-call codes $codes for $packageName")
            return emptyList()
        }

        private fun serviceCallCmd(code: Int, packageName: String, userId: Int): String =
            "service call package $code s16 ${Utils.shQuote(packageName)} $flagsType $SIGNING_FLAGS i32 $userId"
    }

    /** `unzip -l` name column, filtered like [Utils.isTrackedApkEntry]; directories dropped like [LenientZipInputStream.fileNames]. */
    @JvmStatic
    fun parseUnzipList(output: String): List<String> =
        output.lineSequence()
            .mapNotNull { UNZIP_LIST_LINE.matchEntire(it)?.groupValues?.get(1) }
            .filter { !it.endsWith("/") && Utils.isTrackedApkEntry(it) }
            .distinct() // a retried command re-streams its output
            .toList()

    /** `  Length  Date  Time  Name`; name may contain spaces. Header/footer rows don't match. */
    private val UNZIP_LIST_LINE = Regex("""^\s*\d+\s+\S+\s+\S+\s+(.+?)\s*$""")

    /**
     * Scan Parcel bytes for X.509 certs. At each ASN.1 SEQUENCE start (`0x30`), let
     * [CertificateFactory] parse — no hand-rolled DER length decoding.
     * Dedupes by SHA-256 of the encoded cert. Only feed this a `getPackageInfo` reply:
     * the certificates are marked signature-verified on PackageManager's word.
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
            // PackageManager verified this signature when it installed the package.
            val info = CertificateParser.fromX509Certificate(cert, true)
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

    private fun listTrackedEntries(shell: Shell, apkPath: String): List<String> =
        shellOr(emptyList(), "unzip -l failed for $apkPath") {
            val sb = StringBuilder()
            shell.execForEachLine("unzip -l ${Utils.shQuote(apkPath)}") { sb.appendLine(it) }
            parseUnzipList(sb.toString())
        }

    private fun extractManifest(shell: Shell, apkPath: String): ByteArray? =
        shellOr(null, "unzip -p AndroidManifest.xml failed for $apkPath") {
            val buf = ByteArrayOutputStream()
            shell.execToStream("unzip -p ${Utils.shQuote(apkPath)} AndroidManifest.xml", buf)
            buf.toByteArray().takeIf { it.isNotEmpty() }
        }

    /** Null when the command failed, so the caller does not cache it. */
    private fun fetchPmDump(shell: Shell, packageName: String): PmDumpInfo? =
        shellOr(null, "pm dump failed for $packageName") {
            val sb = StringBuilder()
            shell.execForEachLine("pm dump ${Utils.shQuote(packageName)}") { sb.appendLine(it) }
            parsePmDumpOutput(sb.toString())
        }

    /** A command that cannot run degrades to [fallback]; see [Shell]. */
    private inline fun <T> shellOr(fallback: T, what: String, block: () -> T): T =
        try {
            block()
        } catch (e: IOException) {
            LogUtils.w(TAG, "$what: ${e.message}")
            fallback
        }
}
