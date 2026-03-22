package org.osservatorionessuno.libmvt.common.logging

class StdoutLibmvtLogger : LibmvtLogger {

    override fun d(tag: String?, msg: String?) {
        if (msg == null) return
        println(format("D", tag, msg))
    }

    override fun i(tag: String?, msg: String?) {
        if (msg == null) return
        println(format("I", tag, msg))
    }

    override fun w(tag: String?, msg: String?) {
        if (msg == null) return
        println(format("W", tag, msg))
    }

    override fun e(tag: String?, msg: String?, t: Throwable?) {
        if (msg == null && t == null) return
        System.err.println(format("E", tag, msg ?: ""))
        t?.printStackTrace()
    }

    private fun format(level: String, tag: String?, msg: String): String {
        val effectiveTag = if (!tag.isNullOrEmpty()) tag else "libmvt"
        return "$effectiveTag $level: $msg"
    }
}