package org.osservatorionessuno.libmvt.android.parsers

import java.io.File
import java.io.InputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Date
import javax.naming.ldap.LdapName
import javax.security.auth.x500.X500Principal

object CertificateParser {
    data class CertificateInfo(
        val subject: String,
        val issuer: String,
        val notBefore: Date,
        val notAfter: Date,
        val algorithm: String,
        val version: Int,
        val serialNumber: String,
        val checksums: Checksum,
    )
    data class Checksum(
        val md5: String,
        val sha1: String,
        val sha256: String,
    )

    @JvmStatic
    fun formatPrincipal(principal: X500Principal): String {
        var oidMap = mapOf(
            "1.2.840.113549.1.9.1" to "E"
        )
        val ldapName = LdapName(principal.getName(X500Principal.RFC2253, oidMap))
        return ldapName.rdns.joinToString(",") { it.toString() }
    }

    @JvmStatic
    fun fromFile(file: File): CertificateInfo {
        return fromInputStream(file.inputStream())
    }

    @JvmStatic
    fun fromInputStream(inputStream: InputStream): CertificateInfo {
        val cert =
            CertificateFactory.getInstance("X.509").generateCertificate(inputStream) as X509Certificate
        return fromX509Certificate(cert)
    }

    @JvmStatic
    fun fromX509Certificate(cert: X509Certificate): CertificateInfo =
        CertificateInfo(
            subject = formatPrincipal(cert.subjectX500Principal),
            issuer = formatPrincipal(cert.issuerX500Principal),
            notBefore = cert.notBefore,
            notAfter = cert.notAfter,
            algorithm = cert.sigAlgName,
            version = cert.version,
            serialNumber = cert.serialNumber.toString(16),
            checksums =
                Checksum(
                    md5 = certificateFingerprint(cert, "MD5"),
                    sha1 = certificateFingerprint(cert, "SHA1"),
                    sha256 = certificateFingerprint(cert, "SHA-256"),
                ),
        )

    private fun certificateFingerprint(cert: X509Certificate, algorithm: String): String {
        val digest = MessageDigest.getInstance(algorithm).digest(cert.encoded)
        return digest.joinToString(separator = "") { b -> "%02x".format(b) }
    }
}
