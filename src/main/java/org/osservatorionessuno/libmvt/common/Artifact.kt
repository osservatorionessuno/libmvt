package org.osservatorionessuno.libmvt.common

import java.util.function.Consumer

abstract class Artifact {

    @JvmField
    val detected: MutableList<Detection> = mutableListOf()

    @JvmField
    var indicators: Indicators? = null

    /**
     * Receives every record a module parses, in order. Lets a caller consume decoded records
     * (export, display, assertions) without them being retained.
     */
    var recordObserver: Consumer<Any>? = null

    /**
     * Records passed to [emit]. Since none are kept, this is all that distinguishes "parsed
     * nothing" from "parsed plenty and found nothing" — a distinction callers and tests can
     * make, but which the report does not draw yet.
     */
    var recordCount: Long = 0
        private set

    @Throws(Exception::class)
    abstract fun parse(artifactInput: AbstractInput)

    /**
     * Routes a freshly parsed record. Modules call this instead of retaining records, so peak
     * memory does not scale with the artifact's size. The record is checked immediately and then
     * dropped, which means [indicators] must be set *before* [parse] — afterwards there is
     * nothing left to re-check.
     */
    protected fun emit(record: Any) {
        recordCount++
        recordObserver?.accept(record)
        checkRecord(record)
    }

    /** Per-record detection logic. This is where a module does its checking. */
    protected open fun checkRecord(record: Any) = Unit

    /**
     * Final pass after [parse], for detections that need whole-artifact context such as ordering.
     * Most modules check everything in [checkRecord] and need nothing here.
     */
    open fun checkIndicators() = Unit

    /** Folds [other] in, for a path that several modules parse. */
    fun merge(other: Artifact) {
        detected.addAll(other.detected)
        recordCount += other.recordCount
    }

    fun setIndicators(indicators: Indicators?) {
        this.indicators = indicators
    }
}
