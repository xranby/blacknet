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

class SynchronizedHashSet<T>(
        val mutex: Mutex = Mutex(),
        val set: HashSet<T> = HashSet()
) {
    suspend inline fun isEmpty() = mutex.withLock { set.isEmpty() }

    suspend inline fun size() = mutex.withLock { set.size }

    suspend inline fun add(element: T) = mutex.withLock { set.add(element) }

    suspend inline fun remove(element: T) = mutex.withLock { set.remove(element) }

    suspend inline fun contains(element: T) = mutex.withLock { set.contains(element) }

    suspend inline fun clear() = mutex.withLock { set.clear() }

    suspend inline fun toList() = mutex.withLock { set.toList() }

    suspend inline fun filterToList(predicate: (T) -> Boolean) = mutex.withLock { set.filterTo(ArrayList(set.size), predicate) }

    suspend inline fun forEach(action: (T) -> Unit) = mutex.withLock { set.forEach(action) }

    suspend inline fun <R> mapToList(transform: (T) -> R) = mutex.withLock { set.mapTo(ArrayList(set.size), transform) }
}
