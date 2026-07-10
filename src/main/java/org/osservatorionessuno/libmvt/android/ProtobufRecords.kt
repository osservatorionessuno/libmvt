package org.osservatorionessuno.libmvt.android

import com.google.protobuf.CodedInputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream

object ProtobufRecords {
    @JvmStatic
    @Throws(IOException::class)
    fun readDelimited(input: InputStream): ByteArray? {
        val first: Int = input.read()
        if (first == -1) return null
        val size: Int = CodedInputStream.readRawVarint32(first, input)
        if (size < 0) throw IOException("Negative protobuf record size")
        val record: ByteArray = ByteArray(size)
        var offset: Int = 0
        while (offset < size) {
            val read: Int = input.read(record, offset, size - offset)
            if (read < 0) throw EOFException("Unexpected end of protobuf record")
            offset += read
        }
        return record
    }

    @JvmStatic
    @Throws(IOException::class)
    fun forEachDelimited(input: InputStream, block: RecordConsumer) {
        while (true) {
            val record = readDelimited(input) ?: break
            block.accept(record)
        }
    }

    fun interface RecordConsumer {
        @Throws(IOException::class)
        fun accept(record: ByteArray)
    }

    @JvmStatic
    @Throws(IOException::class)
    fun readLengthDelimitedField(input: CodedInputStream): ByteArray {
        val size: Int = input.readRawVarint32()
        return input.readRawBytes(size)
    }

    @JvmStatic
    @Throws(IOException::class)
    fun readString(input: CodedInputStream): String {
        return input.readStringRequireUtf8()
    }

    @JvmStatic
    @Throws(IOException::class)
    fun readStringRecord(record: ByteArray): String {
        val input: CodedInputStream = CodedInputStream.newInstance(record)
        var value: String = ""
        var tag: Int = input.readTag()
        while (tag != 0) {
            if ((tag ushr 3) == STRING_RECORD_FIELD_NUMBER) {
                value = readString(input)
            } else {
                input.skipField(tag)
            }
            tag = input.readTag()
        }
        return value
    }

    private const val STRING_RECORD_FIELD_NUMBER: Int = 1
}
