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
        /** Paths from open_fds and every backtrace frame's file_name. */
        val referencedFiles: Set<String> = emptySet(),
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
        val referencedFiles = linkedSetOf<String>()

        var tag = input.readTag()
        while (tag != 0) {
            when (tag ushr 3) {
                FIELD_TIMESTAMP -> timestamp = input.readStringRequireUtf8()
                FIELD_PID -> pid = input.readUInt32()
                FIELD_TID -> tid = input.readUInt32()
                FIELD_UID -> uid = input.readUInt32()
                FIELD_COMMAND_LINE -> commandLine.add(input.readStringRequireUtf8())
                FIELD_CAUSES -> parseCause(readLengthDelimitedBytes(input), referencedFiles)
                FIELD_THREADS -> parseThreadMapEntry(input, threadNames, referencedFiles)
                FIELD_OPEN_FDS -> parseOpenFd(readLengthDelimitedBytes(input), referencedFiles)
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
            referencedFiles = referencedFiles,
        )
    }

    private fun parseThreadMapEntry(
        input: CodedInputStream,
        threadNames: MutableMap<Int, String>,
        referencedFiles: MutableSet<String>,
    ) {
        val limit = input.pushLimit(input.readRawVarint32())
        var key = 0
        var threadName = ""
        var tag = input.readTag()
        while (tag != 0) {
            when (tag ushr 3) {
                MAP_KEY_FIELD -> key = input.readUInt32()
                MAP_VALUE_FIELD -> {
                    val thread = parseThread(readLengthDelimitedBytes(input))
                    threadName = thread.first
                    for (path in thread.second) addReferencedPath(referencedFiles, path)
                }
                else -> input.skipField(tag)
            }
            tag = input.readTag()
        }
        input.popLimit(limit)
        if (key != 0 && threadName.isNotEmpty()) {
            threadNames[key] = threadName
        }
    }

    /** Returns (thread name, backtrace file paths). */
    private fun parseThread(bytes: ByteArray): Pair<String, List<String>> {
        val input = CodedInputStream.newInstance(bytes)
        var name = ""
        val files = mutableListOf<String>()
        var tag = input.readTag()
        while (tag != 0) {
            when (tag ushr 3) {
                THREAD_NAME_FIELD -> name = input.readStringRequireUtf8()
                THREAD_CURRENT_BACKTRACE_FIELD ->
                    parseBacktraceFrameFileName(readLengthDelimitedBytes(input))?.let { files.add(it) }
                THREAD_UNREADABLE_ELF_FILES_FIELD -> {
                    val path = input.readStringRequireUtf8()
                    if (path.isNotEmpty()) files.add(path)
                }
                else -> input.skipField(tag)
            }
            tag = input.readTag()
        }
        return name to files
    }

    private fun parseOpenFd(bytes: ByteArray, referencedFiles: MutableSet<String>) {
        val input = CodedInputStream.newInstance(bytes)
        var tag = input.readTag()
        while (tag != 0) {
            if ((tag ushr 3) == FD_PATH_FIELD) {
                addReferencedPath(referencedFiles, input.readStringRequireUtf8())
            } else {
                input.skipField(tag)
            }
            tag = input.readTag()
        }
    }

    private fun parseCause(bytes: ByteArray, referencedFiles: MutableSet<String>) {
        val input = CodedInputStream.newInstance(bytes)
        var tag = input.readTag()
        while (tag != 0) {
            if ((tag ushr 3) == CAUSE_MEMORY_ERROR_FIELD) {
                parseMemoryError(readLengthDelimitedBytes(input), referencedFiles)
            } else {
                input.skipField(tag)
            }
            tag = input.readTag()
        }
    }

    private fun parseMemoryError(bytes: ByteArray, referencedFiles: MutableSet<String>) {
        val input = CodedInputStream.newInstance(bytes)
        var tag = input.readTag()
        while (tag != 0) {
            if ((tag ushr 3) == MEMORY_ERROR_HEAP_FIELD) {
                parseHeapObject(readLengthDelimitedBytes(input), referencedFiles)
            } else {
                input.skipField(tag)
            }
            tag = input.readTag()
        }
    }

    private fun parseHeapObject(bytes: ByteArray, referencedFiles: MutableSet<String>) {
        val input = CodedInputStream.newInstance(bytes)
        var tag = input.readTag()
        while (tag != 0) {
            when (tag ushr 3) {
                HEAP_ALLOCATION_BACKTRACE_FIELD,
                HEAP_DEALLOCATION_BACKTRACE_FIELD,
                -> parseBacktraceFrameFileName(readLengthDelimitedBytes(input))?.let {
                    addReferencedPath(referencedFiles, it)
                }
                else -> input.skipField(tag)
            }
            tag = input.readTag()
        }
    }

    private fun parseBacktraceFrameFileName(bytes: ByteArray): String? {
        val input = CodedInputStream.newInstance(bytes)
        var fileName = ""
        var tag = input.readTag()
        while (tag != 0) {
            if ((tag ushr 3) == BACKTRACE_FRAME_FILE_NAME_FIELD) {
                fileName = input.readStringRequireUtf8()
            } else {
                input.skipField(tag)
            }
            tag = input.readTag()
        }
        return fileName.takeIf { it.isNotEmpty() }
    }

    /**
     * Drop suffixes like " (deleted)" that Android includes in /proc and map paths.
     */
    private fun addReferencedPath(referencedFiles: MutableSet<String>, raw: String) {
        val path = raw.substringBefore(' ').trim()
        if (path.isNotEmpty()) referencedFiles.add(path)
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
    private const val FIELD_CAUSES = 15
    private const val FIELD_THREADS = 16
    private const val FIELD_OPEN_FDS = 19
    private const val MAP_KEY_FIELD = 1
    private const val MAP_VALUE_FIELD = 2
    private const val THREAD_NAME_FIELD = 2
    private const val THREAD_CURRENT_BACKTRACE_FIELD = 4
    private const val THREAD_UNREADABLE_ELF_FILES_FIELD = 9
    private const val FD_PATH_FIELD = 2
    private const val CAUSE_MEMORY_ERROR_FIELD = 2
    private const val MEMORY_ERROR_HEAP_FIELD = 3
    private const val HEAP_ALLOCATION_BACKTRACE_FIELD = 4
    private const val HEAP_DEALLOCATION_BACKTRACE_FIELD = 6
    private const val BACKTRACE_FRAME_FILE_NAME_FIELD = 6
}
