/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.util

/**
 * Returns the sum of all values produced by [selector].
 */
inline fun <T> Iterable<T>.sumByFloat(selector: (T) -> Float): Float {
    var sum: Float = 0f
    for (element in this) {
        sum += selector(element)
    }
    return sum
}

/**
 * Returns the sum of all values produced by [selector].
 *
 * @throws ArithmeticException on overflow.
 */
inline fun <T> Iterable<T>.sumByLong(selector: (T) -> Long): Long {
    var sum: Long = 0
    for (element in this) {
        sum = Math.addExact(sum, selector(element))
    }
    return sum
}

/**
 * Returns the sum of all elements.
 *
 * @throws ArithmeticException on overflow.
 */
fun ArrayList<Long>.sumByLong(): Long {
    var sum: Long = 0
    for (i in 0 until size) {
        sum = Math.addExact(sum, this[i])
    }
    return sum
}
