/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.core

import kotlin.math.max
import ninja.blacknet.util.HashMap

abstract class MemPool {
    private var maxSeenSize = 512
    private var map = HashMap<ByteArray, ByteArray>(maxSeenSize)
    private var dataSize = 0

    protected fun stealImpl(): HashMap<ByteArray, ByteArray> {
        val stolen = map
        maxSeenSize = max(maxSeenSize, stolen.size)
        map = HashMap<ByteArray, ByteArray>(maxSeenSize)
        dataSize = 0
        return stolen
    }

    protected fun maxSeenSizeImpl(): Int {
        return maxSeenSize
    }

    fun sizeImpl(): Int {
        return map.size
    }

    fun dataSizeImpl(): Int {
        return dataSize
    }

    fun <T> mapHashesToListImpl(transform: (ByteArray) -> T): MutableList<T> {
        return map.keys.mapTo(ArrayList(map.size), transform)
    }

    protected fun addImpl(hash: ByteArray, bytes: ByteArray) {
        map.put(hash, bytes)
        dataSize += bytes.size
    }

    protected fun containsImpl(hash: ByteArray): Boolean {
        return map.containsKey(hash)
    }

    protected fun getImpl(hash: ByteArray): ByteArray? {
        return map.get(hash)
    }

    protected fun removeImpl(hash: ByteArray) {
        val bytes = map.remove(hash)
        if (bytes != null)
            dataSize -= bytes.size
    }
}
