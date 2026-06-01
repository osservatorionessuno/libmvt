package org.osservatorionessuno.libmvt.common

import java.io.InputStream

abstract class AbstractInput(
    @JvmField val path: String,
    @JvmField val inputStream: InputStream,
)
