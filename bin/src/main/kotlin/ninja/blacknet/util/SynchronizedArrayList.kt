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

class SynchronizedArrayList<T>(
        val mutex: Mutex = Mutex(),
        val list: ArrayList<T> = ArrayList()
) {
    constructor(initialCapacity: Int) : this(list = ArrayList(initialCapacity))

    suspend inline fun isEmpty() = mutex.withLock { list.isEmpty() }

    suspend inline fun size() = mutex.withLock { list.size }

    suspend inline fun add(element: T) = mutex.withLock { list.add(element) }

    suspend inline fun addAll(elements: Collection<T>) = mutex.withLock { list.addAll(elements) }

    suspend inline fun copy() = mutex.withLock { ArrayList(list) }

    suspend inline fun clear() = mutex.withLock { list.clear() }

    suspend inline fun get(index: Int): T = mutex.withLock { list.get(index) }

    suspend inline fun remove(element: T) = mutex.withLock { list.remove(element) }

    suspend inline fun removeIf(noinline filter: (T) -> Boolean) = mutex.withLock { list.removeIf(filter) }

    suspend inline fun forEach(action: (T) -> Unit) = mutex.withLock { for (i in 0 until list.size) action(list[i]) }

    suspend inline fun reversedForEach(action: (T) -> Unit) = mutex.withLock { for (i in list.size - 1 downTo 0) action(list[i]) }

    suspend inline fun find(predicate: (T) -> Boolean) = mutex.withLock { list.find(predicate) }

    suspend inline fun sumBy(selector: (T) -> Int) = mutex.withLock { list.sumBy(selector) }

    suspend inline fun filter(predicate: (T) -> Boolean) = mutex.withLock { list.filterTo(ArrayList(list.size), predicate) }

    suspend inline fun <R : Comparable<R>> maxBy(selector: (T) -> R) = mutex.withLock { list.maxBy(selector) }

    suspend inline fun <R> map(transform: (T) -> R): ArrayList<R> = mutex.withLock { list.mapTo(ArrayList(list.size), transform) }

    suspend inline fun removeFirstIf(filter: (T) -> Boolean): T? = mutex.withLock {
        val i = list.indexOfFirst(filter)
        if (i == -1) return@withLock null
        return@withLock list.removeAt(i)
    }
}
