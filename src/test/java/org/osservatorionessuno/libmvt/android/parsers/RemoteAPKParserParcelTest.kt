package org.osservatorionessuno.libmvt.android.parsers

import com.android.apksig.ApkVerifier
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.osservatorionessuno.libmvt.ResourcesUtils
import org.osservatorionessuno.libmvt.android.analyzer.APKStaticAnalyzer
import org.osservatorionessuno.libmvt.common.Utils
import java.io.File
import java.io.OutputStream
import java.util.zip.ZipFile

class RemoteAPKParserParcelTest {
    @BeforeEach
    fun resetServiceCallCache() {
        RemoteAPKParser.resetCachedServiceCallCode()
    }

    @Test
    fun parcelBytesFromServiceCallOutput_extractsAndroidDebugCert() {
        val output = ResourcesUtils.readResourceString("remote_apk/service_call_get_signatures.txt")
        val parcel = Utils.parcelBytesFromServiceCallOutput(output)
        assertTrue(parcel.size > 1000, "expected a PackageInfo-sized parcel, got ${parcel.size}")

        val certs = RemoteAPKParser.certificatesFromParcelBytes(parcel)
        assertEquals(1, certs.size)
        val cert = certs[0]
        assertTrue(cert.subject.contains("Android Debug"), "subject=${cert.subject}")
        assertEquals("8d1db85f19ae87349d423232510710bbe9694c87", cert.checksums.sha1)
        // PM-attested only — never trusted without apksig verify.
        assertFalse(cert.trusted)
    }

    @Test
    fun certificatesFromParcelBytes_emptyOrGarbageYieldsNothing() {
        assertTrue(RemoteAPKParser.certificatesFromParcelBytes(ByteArray(0)).isEmpty())
        assertTrue(RemoteAPKParser.certificatesFromParcelBytes(ByteArray(64) { 0x41 }).isEmpty())
    }

    @Test
    fun certificatesFromParcelBytes_extractsSignerDerFromSignedApk() {
        val apk = ResourcesUtils.readResourceFile("apks/signed_test.apk")
        val der = signerDer(apk)
        val certs = RemoteAPKParser.certificatesFromParcelBytes(der)
        assertEquals(1, certs.size)
        assertTrue(certs[0].subject.contains("LibMVT"), "subject=${certs[0].subject}")
        assertFalse(certs[0].trusted)

        val local = APKParser.parseAPK(apk)
        assertEquals(local.certificates[0].checksums.sha1, certs[0].checksums.sha1)
        assertEquals(local.certificates[0].checksums.sha256, certs[0].checksums.sha256)
    }

    @Test
    fun certificatesFromParcelBytes_dedupesRepeatedDer() {
        val der = signerDer(ResourcesUtils.readResourceFile("apks/signed_test.apk"))
        val doubled = der + ByteArray(8) + der
        assertEquals(1, RemoteAPKParser.certificatesFromParcelBytes(doubled).size)
    }

    @Test
    fun certificatesFromParcelBytes_skipsTruncatedSequence() {
        // Claim a long length but only supply a few trailing bytes.
        val truncated = byteArrayOf(0x30, 0x82.toByte(), 0x01, 0x00, 0x01, 0x02, 0x03)
        assertTrue(RemoteAPKParser.certificatesFromParcelBytes(truncated).isEmpty())
    }

    @Test
    fun certificatesFromServiceCallHex_roundTripsSignerDer() {
        val apk = ResourcesUtils.readResourceFile("apks/signed_test.apk")
        val der = signerDer(apk)
        val pkg = "org.osservatorionessuno.libmvt.test"
        val parcelPayload = pkg.toByteArray(Charsets.UTF_8) + der
        val dump = formatServiceCallDump(parcelPayload)
        val certs = RemoteAPKParser.certificatesFromParcelBytes(
            Utils.parcelBytesFromServiceCallOutput(dump),
        )
        assertEquals(1, certs.size)
        assertEquals(APKParser.parseAPK(apk).certificates[0].checksums.sha1, certs[0].checksums.sha1)
    }

    @Test
    fun parseUnzipList_keepsTrackedPrefixesOnly() {
        val listing = """
            Archive:  /data/app/example/base.apk
              Length      Date    Time    Name
            ---------  ---------- -----   ----
                   45  1981-01-01 01:01   assets/with space.bin
                21280  1981-01-01 01:01   AndroidManifest.xml
                   10  1981-01-01 01:01   assets/foo.bin
                   20  1981-01-01 01:01   res/raw/cfg.xml
                   30  1981-01-01 01:01   res/xml/network.xml
                   40  1981-01-01 01:01   lib/arm64-v8a/libx.so
                   50  1981-01-01 01:01   classes.dex
            ---------                     -------
                21430                     6 files
        """.trimIndent()
        assertEquals(
                "assets/with space.bin",
            listOf(
                "assets/foo.bin",
                "res/raw/cfg.xml",
                "res/xml/network.xml",
                "lib/arm64-v8a/libx.so",
            ),
            RemoteAPKParser.parseUnzipList(listing),
        )
    }

    @Test
    fun parsePmDumpOutput_readsVersionAndPermissions() {
        val dump = """
            Packages:
              Package [com.example.app] (abc):
                versionCode=9 minSdk=30 targetSdk=36
                versionName=0.2.3
                signatures=PackageSignatures{aaa version:2, signatures:[ad7d173d], past signatures:[]}
            Hidden system packages:
              Package [com.example.app] (def):
                versionCode=1 minSdk=30 targetSdk=36
                versionName=0.0.1
                requested permissions:
                  android.permission.READ_SMS
                requested permissions:
                  android.permission.CAMERA
                  android.permission.RECORD_AUDIO
                install permissions:
                  android.permission.INTERNET: granted=true
        """.trimIndent()
        val info = RemoteAPKParser.parsePmDumpOutput(dump)
        assertEquals("0.2.3", info.versionName)
        assertEquals("9", info.versionCode)
        assertEquals(
            listOf("android.permission.CAMERA", "android.permission.RECORD_AUDIO"),
            info.requestedPermissions,
        )
    }

    @Test
    fun permissionsLookSuspicious_extraDangerousTriggers() {
        assertTrue(
            APKStaticAnalyzer.permissionsLookSuspicious(
                listOf("android.permission.REQUEST_INSTALL_PACKAGES"),
            ),
        )
        assertFalse(
            APKStaticAnalyzer.permissionsLookSuspicious(
                listOf("android.permission.INTERNET"),
            ),
        )
    }

    @Test
    fun isTrackedApkEntry_matchesApkParserPrefixes() {
        assertTrue(Utils.isTrackedApkEntry("assets/x"))
        assertTrue(Utils.isTrackedApkEntry("lib/arm64/lib.so"))
        assertFalse(Utils.isTrackedApkEntry("classes.dex"))
        assertFalse(Utils.isTrackedApkEntry("AndroidManifest.xml"))
    }

    @Test
    fun remoteAndLocalAgreeOnSignedTestApk() {
        assertRemoteMatchesLocal("apks/signed_test.apk")
    }

    @Test
    fun remoteAndLocalAgreeOnTamperedTestApk() {
        assertRemoteMatchesLocal("apks/tampered_test.apk")
    }

    private fun assertRemoteMatchesLocal(resource: String) {
        val apk = ResourcesUtils.readResourceFile(resource)
        val local = APKParser.parseAPK(apk)
        val remote = RemoteAPKParser.parse(
            LocalApkShell(apk, local.packageName),
            local.packageName,
            apk.absolutePath,
        )

        assertEquals(local.packageName, remote.packageName)
        assertEquals(local.versionCode, remote.versionCode)
        assertEquals(local.versionName, remote.versionName)
        assertEquals(local.files.sorted(), remote.files.sorted())
        assertEquals(local.suspicious, remote.suspicious)
        // Remote never claims apksig verification.
        assertFalse(remote.verified)
        assertEquals(
            local.certificates.map { it.checksums.sha1 }.sorted(),
            remote.certificates.map { it.checksums.sha1 }.sorted(),
        )
        assertEquals(
            local.certificates.map { it.checksums.sha256 }.sorted(),
            remote.certificates.map { it.checksums.sha256 }.sorted(),
        )
        assertTrue(remote.certificates.all { !it.trusted })
    }

    /** Simulates device shell tools by answering from a local APK file. */
    private class LocalApkShell(
        private val apk: File,
        private val packageName: String,
    ) : RemoteAPKParser.Shell {
        private val der: ByteArray = signerDer(apk)

        override fun execForEachLine(command: String, onLine: (String) -> Unit) {
            when {
                command.startsWith("unzip -l ") ->
                    unzipListOutput().lineSequence().forEach(onLine)
                command.startsWith("pm dump ") ->
                    pmDumpOutput().lineSequence().forEach(onLine)
                command.startsWith("service call package ") ->
                    formatServiceCallDump(packageName.toByteArray(Charsets.UTF_8) + der)
                        .lineSequence()
                        .forEach(onLine)
            }
        }

        override fun execToStream(command: String, output: OutputStream) {
            if (!command.contains("AndroidManifest.xml")) return
            ZipFile(apk).use { zip ->
                val entry = zip.getEntry("AndroidManifest.xml") ?: return
                zip.getInputStream(entry).use { it.copyTo(output) }
            }
        }

        private fun unzipListOutput(): String {
            val sb = StringBuilder()
            sb.appendLine("Archive:  ${apk.absolutePath}")
            sb.appendLine("  Length      Date    Time    Name")
            sb.appendLine("---------  ---------- -----   ----")
            ZipFile(apk).use { zip ->
                for (entry in zip.entries()) {
                    if (entry.isDirectory) continue
                    sb.appendLine(
                        "%9d  1981-01-01 01:01   %s".format(entry.size, entry.name),
                    )
                }
            }
            sb.appendLine("---------                     -------")
            sb.appendLine("        0                     0 files")
            return sb.toString()
        }

        private fun pmDumpOutput(): String =
            """
            Packages:
              Package [$packageName] (deadbeef):
                versionCode=0 minSdk=1 targetSdk=1
                versionName=from-pm-dump
                requested permissions:
            """.trimIndent()
    }

    companion object {
        private fun signerDer(apk: File): ByteArray {
            val result = ApkVerifier.Builder(apk).build().verify()
            val cert = result.signerCertificates.firstOrNull()
                ?: result.v2SchemeSigners.firstOrNull()?.certificate
                ?: result.v3SchemeSigners.firstOrNull()?.certificate
                ?: result.v1SchemeSigners.firstOrNull()?.certificate
                ?: error("no signer certificate in ${apk.name}")
            return cert.encoded
        }

        /** Format raw bytes as a `service call` hex dump (`0xADDR: w0 w1 w2 w3`). */
        private fun formatServiceCallDump(payload: ByteArray): String {
            val pad = (4 - payload.size % 4) % 4
            val bytes = if (pad == 0) payload else payload + ByteArray(pad)
            val sb = StringBuilder("Result: Parcel(\n")
            var offset = 0
            while (offset < bytes.size) {
                val end = minOf(offset + 16, bytes.size)
                val words = ArrayList<String>(4)
                var i = offset
                while (i + 3 < end) {
                    val w =
                        (bytes[i].toInt() and 0xff) or
                            ((bytes[i + 1].toInt() and 0xff) shl 8) or
                            ((bytes[i + 2].toInt() and 0xff) shl 16) or
                            ((bytes[i + 3].toInt() and 0xff) shl 24)
                    words.add("%08x".format(w.toLong() and 0xffffffffL))
                    i += 4
                }
                sb.append("0x%08x: %s ''\n".format(offset, words.joinToString(" ")))
                offset = end
            }
            sb.append(")\n")
            return sb.toString()
        }
    }
}
