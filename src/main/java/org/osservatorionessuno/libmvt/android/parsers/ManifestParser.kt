package org.osservatorionessuno.libmvt.android.parsers

import android.content.res.AXMLResource
import org.osservatorionessuno.libmvt.android.parsers.axml.CompressedXmlDomListener
import org.osservatorionessuno.libmvt.android.parsers.axml.CompressedXmlParser
import org.osservatorionessuno.libmvt.common.logging.LogUtils
import org.w3c.dom.Document
import java.io.BufferedInputStream
import java.io.IOException
import java.io.InputStream
import java.io.StringReader
import java.lang.reflect.InvocationTargetException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import javax.xml.XMLConstants
import javax.xml.parsers.DocumentBuilderFactory
import org.xml.sax.InputSource

class ManifestParser {
    data class ManifestInfo(
        val packageName: String,
        val versionCode: String,
        val versionName: String,
    )

    companion object {
        private const val ANDROID_NS = "http://schemas.android.com/apk/res/android"
    }

    /**
     *Function to extract the manifest information from an XML Document.
     */
    private fun manifestInfoFromDocument(document: Document): ManifestInfo {
        val el = document.documentElement ?: return ManifestInfo("", "", "")
        val packageName = el.getAttribute("package")
        val versionCode =
            el.getAttributeNS(ANDROID_NS, "versionCode").ifEmpty {
                el.getAttribute("android:versionCode")
            }
        val versionName =
            el.getAttributeNS(ANDROID_NS, "versionName").ifEmpty {
                el.getAttribute("android:versionName")
            }
        return ManifestInfo(
            packageName = packageName,
            versionCode = versionCode,
            versionName = versionName,
        )
    }

    /**
     * Helper function to print an XML Document to the console for debugging purposes.
     */
    private fun _printDocument(document: Document) {
        val transformerFactory = javax.xml.transform.TransformerFactory.newInstance()
        val transformer = transformerFactory.newTransformer().apply {
            setOutputProperty(javax.xml.transform.OutputKeys.INDENT, "yes")
            setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2")
        }
        val source = javax.xml.transform.dom.DOMSource(document)
        val writer = java.io.StringWriter()
        val result = javax.xml.transform.stream.StreamResult(writer)
        transformer.transform(source, result)
        LogUtils.i("ManifestParser", "Document:\n${writer.toString()}")
    }

    /**
     * Uses the Stanley AXML parser to parse the manifest.
     */
    private fun _parseManifest(input: InputStream): Document {
        val dom = CompressedXmlDomListener()
        CompressedXmlParser().parse(input, dom)
        return dom.getXmlDocument()
    }

    /**
     * Uses [rednaga/axmlprinter](https://github.com/rednaga/axmlprinter)
     */
    @Throws(IOException::class)
    private fun _parseManifestWithAxmlprinter(input: InputStream): Document {
        val xml = AXMLResource(input).toXML()

        val factory = DocumentBuilderFactory.newInstance()
        factory.isNamespaceAware = true
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        val builder = factory.newDocumentBuilder()
        val document = builder.parse(InputSource(StringReader(xml)))
        return document
    }

    /**
     * Parses an Android compressed XML manifest from an InputStream.
     * If useLibrary is true, uses the axmlprinter library to parse the manifest.
     * Otherwise, uses the Stanley AXML parser.
     */
    fun parseManifest(input: InputStream, useLibrary: Boolean = false): ManifestInfo {
        var document: Document
        if (!useLibrary) {
            LogUtils.d("ManifestParser", "Parsing manifest with Stanley AXML embeddedparser")
            document = _parseManifest(input)
        } else {
            LogUtils.d("ManifestParser", "Parsing manifest with axmlprinter library")
            document = _parseManifestWithAxmlprinter(input)
        }
        
        return manifestInfoFromDocument(document)
    }
}
