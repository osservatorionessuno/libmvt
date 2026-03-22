package org.osservatorionessuno.libmvt.android.parsers.axml

/*
Copyright 2014-2024 XGouchet (xgouchet[at]gmail.com)
Copyright 2026 TheZ3ro (davide@osservatorionessuno.org)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Original source: https://github.com/xgouchet/Stanley/
*/

import org.w3c.dom.Document
import org.w3c.dom.Node
import java.util.Stack
import javax.xml.parsers.DocumentBuilderFactory
import org.osservatorionessuno.libmvt.android.parsers.axml.CompressedXmlParserListener
import org.osservatorionessuno.libmvt.android.parsers.axml.Identifier
import org.osservatorionessuno.libmvt.android.parsers.axml.Attribute
import org.osservatorionessuno.libmvt.common.logging.LogUtils

class CompressedXmlDomListener : CompressedXmlParserListener {

    private val stack: Stack<Node> = Stack()
    private val documentBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder()
    private lateinit var document: Document

    fun getXmlDocument(): Document = document

    // region CompressedXmlParserListener

    override fun startDocument() {
        document = documentBuilder.newDocument()
        stack.push(document)
    }

    override fun endDocument() {
    }

    override fun startPrefixMapping(prefix: String?, uri: String) {
    }

    override fun endPrefixMapping(prefix: String?, uri: String) {
    }

    override fun startElement(identifier: Identifier, attributes: Collection<Attribute>) {
        val element = if (identifier.namespaceUri == null) {
            document.createElement(identifier.localName)
        } else {
            document.createElementNS(identifier.namespaceUri, identifier.qualifiedName)
        }

        for (attr: Attribute in attributes) {
            if (attr.identifier.namespaceUri == null) {
                if (attr.identifier.localName.isNotBlank()) {
                    element.setAttribute(attr.identifier.localName, attr.value)
                }
            } else {
                LogUtils.d("CompressedXmlDomListener", "Setting attribute: ${attr.identifier.namespaceUri}:${attr.identifier.qualifiedName} = ${attr.value}")
                element.setAttributeNS(
                    attr.identifier.namespaceUri,
                    attr.identifier.qualifiedName,
                    attr.value
                )
            }
        }

        stack.peek().appendChild(element)
        stack.push(element)
    }

    override fun endElement(identifier: Identifier) {
        stack.pop()
    }

    override fun text(data: String) {
        stack.peek().appendChild(document.createTextNode(data))
    }

    override fun characterData(data: String) {
        stack.peek().appendChild(document.createCDATASection(data))
    }

    override fun processingInstruction(target: String, data: String?) {
    }

    // endregion
}