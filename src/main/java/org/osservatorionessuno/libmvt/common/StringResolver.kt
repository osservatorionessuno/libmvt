package org.osservatorionessuno.libmvt.common

import org.w3c.dom.Node
import java.io.InputStream
import javax.xml.parsers.DocumentBuilderFactory

interface StringResolver {

    fun get(name: String): String

}

/**
 * A string resolver for JVM.
 * This resolver read an android-like strings.xml file and load string from it.
 * In this way, we can re-use Bugbane's strings.xml file.
 */
class JvmMapStringResolver(
    private val jvmStrings: Map<String, String>
) : StringResolver {

    constructor() : this(loadDefaultStrings())

    override fun get(name: String): String {
        return jvmStrings[name] ?: ""
    }

    companion object {

        private fun parseStringsXml(xml: InputStream): Map<String, String> {
            val map = HashMap<String, String>()
            try {
                val factory = DocumentBuilderFactory.newInstance()
                factory.isNamespaceAware = false
                factory.isExpandEntityReferences = false
                factory.setFeature("http://xml.org/sax/features/external-general-entities", false)
                factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false)

                val doc = factory.newDocumentBuilder().parse(xml)
                val children = doc.documentElement.childNodes
                for (i in 0 until children.length) {
                    val n = children.item(i)
                    if (n.nodeType != Node.ELEMENT_NODE.toShort()) continue
                    if (n.nodeName != "string") continue

                    val attrs = n.attributes ?: continue
                    val nameAttr = attrs.getNamedItem("name") ?: continue
                    val key = nameAttr.nodeValue
                    val value = n.textContent
                    if (!key.isNullOrEmpty() && value != null) {
                        map[key] = value
                    }
                }
            } catch (ignored: Throwable) {
                // On any error, fall back to empty map.
            } finally {
                try {
                    xml.close()
                } catch (_: Throwable) {
                    // ignore
                }
            }
            return map
        }

        private fun loadDefaultStrings(): Map<String, String> {
            val stream = JvmMapStringResolver::class.java.classLoader
                ?.getResourceAsStream("strings.xml")
                ?: return emptyMap()

            return parseStringsXml(stream)
        }
    }
}

