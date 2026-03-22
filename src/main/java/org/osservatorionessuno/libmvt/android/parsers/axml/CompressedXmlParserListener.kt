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

import org.osservatorionessuno.libmvt.android.parsers.axml.Identifier
import org.osservatorionessuno.libmvt.android.parsers.axml.Attribute

interface CompressedXmlParserListener {

    /**
     * Receive notification of the beginning of a document.
     */
    fun startDocument()

    /**
     * Receive notification of the end of a document.
     */
    fun endDocument()

    /**
     * Begin the scope of a prefix-URI Namespace mapping.
     *
     * @param prefix  the Namespace prefix being declared. An empty string is used
     * for the default element namespace, which has no prefix.
     * @param uri  the Namespace URI the prefix is mapped to
     */
    fun startPrefixMapping(prefix: String?, uri: String)

    /**
     * End the scope of a prefix-URI mapping.
     *
     * @param prefix the prefix that was being mapped. This is the empty string
     * when a default mapping scope ends.
     * @param uri  the Namespace URI the prefix is mapped to
     */
    fun endPrefixMapping(prefix: String?, uri: String)

    /**
     * Receive notification of the beginning of an element.
     *
     * @param identifier  the element identifier
     * @param attributes  the attributes attached to the element. If there are no
     * attributes, it shall be an empty Attributes array. The value
     * of this object after startElement returns is undefined
     */
    fun startElement(
        identifier: Identifier,
        attributes: Collection<Attribute>
    )

    /**
     * Receive notification of the end of an element.
     *
     * @param identifier  the element identifier
     */
    fun endElement(identifier: Identifier)

    /**
     * Receive notification of text.
     *
     * @param data the text data
     */
    fun text(data: String)

    /**
     * Receive notification of character data (in a `<![CDATA[ ]]>` block).
     * @param data the text data
     */
    fun characterData(data: String)

    /**
     * Receive notification of a processing instruction.
     *
     * @param target the processing instruction target
     * @param data the processing instruction data, or null if none was supplied.
     * The data does not include any whitespace separating it from
     * the target
     */
    fun processingInstruction(target: String, data: String?)
}