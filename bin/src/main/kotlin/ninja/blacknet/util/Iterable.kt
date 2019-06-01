/*
 * Copyright (c) 2018 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.util

inline fun <T> Iterable<T>.sumByLong(selector: (T) -> Long): Long {
    var sum: Long = 0
    for (element in this) {
        sum = Math.addExact(sum, selector(element))
    }
    return sum
}

fun ArrayList<Long>.sumByLong(): Long {
    var sum: Long = 0
    for (i in this.indices) {
        sum = Math.addExact(sum, this[i])
    }
    return sum
}
