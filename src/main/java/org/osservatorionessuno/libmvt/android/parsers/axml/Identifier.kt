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

data class Identifier(
    val localName: String,
    val namespaceUri: String?,
    val namespacePrefix: String?,
    val qualifiedName: String
) {
    override fun toString(): String {
        return if (namespaceUri == null) {
            "Identifier(“$localName”)"
        } else {
            "Identifier(“$qualifiedName”, $namespaceUri)"
        }
    }
}