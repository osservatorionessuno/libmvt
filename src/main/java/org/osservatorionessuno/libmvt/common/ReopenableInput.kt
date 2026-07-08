package org.osservatorionessuno.libmvt.common

import java.io.InputStream

/**
 * Supplies a new [InputStream] on every [open] call.
 * Required when several modules parse the same path and each reads from the start.
 */
fun interface InputStreamSupplier {
    fun open(): InputStream
}

/**
 * Acquisition file identified by [path] with a reopenable byte source.
 * Used by [org.osservatorionessuno.libmvt.android.ForensicRunner] entry points;
 * modules still receive [AbstractInput] with a single open stream per invocation.
 */
class ReopenableInput private constructor(
    @JvmField val path: String,
    private val supplier: InputStreamSupplier,
) {
    fun openStream(): InputStream = supplier.open()

    companion object {
        @JvmStatic
        fun of(path: String, supplier: InputStreamSupplier): ReopenableInput =
            ReopenableInput(path, supplier)
    }
}
