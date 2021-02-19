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
 * Byte array utilities.
 */

private val EMPTY_BYTE_ARRAY = ByteArray(0)

/**
 * Returns an empty [ByteArray].
 */
fun emptyByteArray(): ByteArray {
    return EMPTY_BYTE_ARRAY
}

/**
 * Returns a [ByteArray] containing the specified bytes represented as [Int]s.
 */
fun byteArrayOfInts(vararg ints: Int): ByteArray {
    return ByteArray(ints.size) { index -> ints[index].toByte() }
}

/**
 * Returns an array containing this byte and then the given [ByteArray].
 */
operator fun Byte.plus(bytes: ByteArray): ByteArray {
    val result = ByteArray(Byte.SIZE_BYTES + bytes.size)
    result[0] = this
    System.arraycopy(bytes, 0, result, Byte.SIZE_BYTES, bytes.size)
    return result
}
