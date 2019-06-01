/*
 * Copyright (c) 2018 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.core

import ninja.blacknet.crypto.Hash
import ninja.blacknet.util.SynchronizedHashMap

abstract class MemPool : DataDB() {
    private val map = SynchronizedHashMap<Hash, ByteArray>()

    suspend fun clear() {
        return map.clear()
    }

    suspend fun copy(): HashMap<Hash, ByteArray> {
        return map.copy()
    }

    suspend fun size(): Int {
        return map.size()
    }

    suspend fun dataSize(): Int {
        return map.sumValuesBy { it.size }
    }

    suspend fun <T> mapHashesToList(transform: (Hash) -> T): MutableList<T> {
        return map.mapKeysToList(transform)
    }

    protected suspend fun add(hash: Hash, bytes: ByteArray) {
        map.put(hash, bytes)
    }

    override suspend fun containsImpl(hash: Hash): Boolean {
        return map.containsKey(hash)
    }

    override suspend fun get(hash: Hash): ByteArray? {
        return map.get(hash)
    }

    suspend fun remove(hash: Hash) {
        map.remove(hash)
    }
}
