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

/**
 * @return value of a Little Endian 32 bit word from the byte array at the given index
 */
@Suppress("MagicNumber")
fun ByteArray.getLEWord(index: Int): Int {
    return (
        get(index + 3).toInt() shl 24 and -0x1000000
            or (get(index + 2).toInt() shl 16 and 0x00ff0000)
            or (get(index + 1).toInt() shl 8 and 0x0000ff00)
            or (get(index + 0).toInt() shl 0 and 0x000000ff)
        )
}

/**
 * @return value of a Little Endian 16 bit word from the byte array at the given index
 */
@Suppress("MagicNumber")
fun ByteArray.getLEShort(off: Int): Int {
    return (
        get(off + 1).toInt() shl 8 and 0xff00
            or (get(off + 0).toInt() shl 0 and 0x00ff)
        )
}