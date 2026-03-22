package org.osservatorionessuno.libmvt.common.logging

/**
 * Simple logging abstraction used by libmvt.
 *
 * Host applications (e.g. Bugbane) can provide their own implementation.
 */
interface LibmvtLogger {
    fun d(tag: String?, msg: String?)
    
    fun i(tag: String?, msg: String?)

    fun w(tag: String?, msg: String?)

    fun e(tag: String?, msg: String?, t: Throwable?)
}