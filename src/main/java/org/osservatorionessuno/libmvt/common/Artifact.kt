package org.osservatorionessuno.libmvt.common

abstract class Artifact {

    @JvmField
    val results: MutableList<Any?> = mutableListOf()

    @JvmField
    val detected: MutableList<Detection> = mutableListOf()

    @JvmField
    var indicators: Indicators? = null

    @Throws(Exception::class)
    abstract fun parse(artifactInput: AbstractInput)

    abstract fun checkIndicators()

    fun setIndicators(indicators: Indicators?) {
        this.indicators = indicators
    }

    fun getResults(): MutableList<Any?> = results
}

