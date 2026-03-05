package org.osservatorionessuno.libmvt.common.logging

object LogUtils {

    @Volatile
    private var logger: LibmvtLogger = StdoutLibmvtLogger()

    @JvmStatic
    fun setLogger(logger: LibmvtLogger?) {
        this.logger = logger ?: StdoutLibmvtLogger()
    }

    @JvmStatic
    fun i(tag: String?, msg: String?) {
        logger.i(tag, msg)
    }

    @JvmStatic
    fun w(tag: String?, msg: String?) {
        logger.w(tag, msg)
    }

    @JvmStatic
    fun e(tag: String?, msg: String?, t: Throwable?) {
        logger.e(tag, msg, t)
    }
}