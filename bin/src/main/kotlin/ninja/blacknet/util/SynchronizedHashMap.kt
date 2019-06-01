/*
 * Copyright (c) 2018 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.util

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

class SynchronizedHashMap<K, V>(
        val mutex: Mutex = Mutex(),
        val map: HashMap<K, V> = HashMap()
) {
    constructor(expectedSize: Int, loadFactor: Float = DEFAULT_LOAD_FACTOR) : this(map = HashMap(capacity(expectedSize, loadFactor), loadFactor))

    suspend inline fun copy() = mutex.withLock { HashMap(map) }

    suspend inline fun clear() = mutex.withLock { map.clear() }

    suspend inline fun isEmpty() = mutex.withLock { map.isEmpty() }

    suspend inline fun keys() = mutex.withLock { ArrayList(map.keys) }

    suspend inline fun size() = mutex.withLock { map.size }

    suspend inline fun get(key: K): V? = mutex.withLock { map.get(key) }

    suspend inline fun put(key: K, value: V) = mutex.withLock { map.put(key, value) }

    suspend inline fun putAll(m: Map<K, V>) = mutex.withLock { map.putAll(m) }

    suspend inline fun putIfAbsent(key: K, value: V): V? = mutex.withLock { map.putIfAbsent(key, value) }

    suspend inline fun remove(key: K) = mutex.withLock { map.remove(key) }

    suspend inline fun removeAll(keys: ArrayList<K>) = mutex.withLock { for (i in keys.indices) map.remove(keys[i]) }

    suspend inline fun containsKey(key: K) = mutex.withLock { map.containsKey(key) }

    suspend inline fun sumValuesBy(selector: (V) -> Int) = mutex.withLock { map.values.sumBy(selector) }

    suspend inline fun <R> mapKeysToList(transform: (K) -> R) = mutex.withLock { map.keys.mapTo(ArrayList(map.size), transform) }

    suspend inline fun forEach(action: (Map.Entry<K, V>) -> Unit) = mutex.withLock { map.forEach(action) }

    suspend inline fun filterToKeyList(predicate: (K, V) -> Boolean) = mutex.withLock {
        val result = ArrayList<K>(map.size)
        for (entry in map) {
            if (predicate(entry.key, entry.value)) {
                result.add(entry.key)
            }
        }
        return@withLock result
    }

    companion object {
        private const val DEFAULT_LOAD_FACTOR = 0.75f

        private fun capacity(expectedSize: Int, loadFactor: Float) = (expectedSize / loadFactor + 1F).toInt()
    }
}
