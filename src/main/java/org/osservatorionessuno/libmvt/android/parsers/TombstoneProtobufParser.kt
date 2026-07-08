package org.osservatorionessuno.libmvt.android.parsers

import com.google.protobuf.CodedInputStream

/**
 * Minimal tombstone.proto parser using protobuf-javalite wire APIs only.
 * Schema: https://android.googlesource.com/platform/system/core/+/refs/heads/main/debuggerd/proto/tombstone.proto
 */
object TombstoneProtobufParser {

    data class Parsed(
        val timestamp: String = "",
        val pid: Int = 0,
        val tid: Int = 0,
        val uid: Int = 0,
        val commandLine: List<String> = emptyList(),
        val threadNames: Map<Int, String> = emptyMap(),
    ) {
        fun processName(): String? = threadNames[tid]?.takeIf { it.isNotEmpty() }
    }

    fun parse(bytes: ByteArray): Parsed {
        val input = CodedInputStream.newInstance(bytes)
        var timestamp = ""
        var pid = 0
        var tid = 0
        var uid = 0
        val commandLine = mutableListOf<String>()
        val threadNames = mutableMapOf<Int, String>()

        var tag = input.readTag()
        while (tag != 0) {
            when (tag ushr 3) {
                FIELD_TIMESTAMP -> timestamp = input.readStringRequireUtf8()
                FIELD_PID -> pid = input.readUInt32()
                FIELD_TID -> tid = input.readUInt32()
                FIELD_UID -> uid = input.readUInt32()
                FIELD_COMMAND_LINE -> commandLine.add(input.readStringRequireUtf8())
                FIELD_THREADS -> parseThreadMapEntry(input, threadNames)
                else -> input.skipField(tag)
            }
            tag = input.readTag()
        }

        return Parsed(
            timestamp = timestamp,
            pid = pid,
            tid = tid,
            uid = uid,
            commandLine = commandLine,
            threadNames = threadNames,
        )
    }

    private fun parseThreadMapEntry(input: CodedInputStream, threadNames: MutableMap<Int, String>) {
        val limit = input.pushLimit(input.readRawVarint32())
        var key = 0
        var threadName = ""
        var tag = input.readTag()
        while (tag != 0) {
            when (tag ushr 3) {
                MAP_KEY_FIELD -> key = input.readUInt32()
                MAP_VALUE_FIELD -> threadName = parseThreadName(readLengthDelimitedBytes(input))
                else -> input.skipField(tag)
            }
            tag = input.readTag()
        }
        input.popLimit(limit)
        if (key != 0 && threadName.isNotEmpty()) {
            threadNames[key] = threadName
        }
    }

    private fun parseThreadName(bytes: ByteArray): String {
        val input = CodedInputStream.newInstance(bytes)
        var name = ""
        var tag = input.readTag()
        while (tag != 0) {
            if ((tag ushr 3) == THREAD_NAME_FIELD) {
                name = input.readStringRequireUtf8()
            } else {
                input.skipField(tag)
            }
            tag = input.readTag()
        }
        return name
    }

    private fun readLengthDelimitedBytes(input: CodedInputStream): ByteArray {
        val size = input.readRawVarint32()
        return input.readRawBytes(size)
    }

    private const val FIELD_TIMESTAMP = 4
    private const val FIELD_PID = 5
    private const val FIELD_TID = 6
    private const val FIELD_UID = 7
    private const val FIELD_COMMAND_LINE = 9
    private const val FIELD_THREADS = 16
    private const val MAP_KEY_FIELD = 1
    private const val MAP_VALUE_FIELD = 2
    private const val THREAD_NAME_FIELD = 2
}
