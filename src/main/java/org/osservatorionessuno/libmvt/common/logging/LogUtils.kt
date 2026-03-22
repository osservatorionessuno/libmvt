package org.osservatorionessuno.libmvt.common.logging

object LogUtils {

    @Volatile
    private var debugEnabled: Boolean = false

    @Volatile
    private var logger: LibmvtLogger = StdoutLibmvtLogger()

    @JvmStatic
    fun setDebugEnabled(enabled: Boolean) {
        debugEnabled = enabled
    }

    @JvmStatic
    fun isDebugEnabled(): Boolean = debugEnabled

    @JvmStatic
    fun setLogger(logger: LibmvtLogger?) {
        this.logger = logger ?: StdoutLibmvtLogger()
    }

    @JvmStatic
    fun d(tag: String?, msg: String?) {
        if (!debugEnabled) return
        logger.d(tag, msg)
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
    fun e(tag: String?, msg: String?, t: Throwable? = null) {
        logger.e(tag, msg, t)
    }
}