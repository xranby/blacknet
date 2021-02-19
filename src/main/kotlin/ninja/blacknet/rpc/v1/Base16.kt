/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

@file:Suppress("DEPRECATION")

package ninja.blacknet.rpc.v1

import kotlin.jvm.Throws

private val HEX_CHARS = charArrayOf('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F')
private val HEX_CHARS_LOWER = charArrayOf('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f')
private val HEX_DECODE_TABLE = byteArrayOf(-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, -1, -1, -1, -1, -1, -1, -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 10, 11, 12, 13, 14, 15)

private fun decodeTable(character: Char): Int {
    val index = character.toInt()
    try {
        val v = HEX_DECODE_TABLE[index].toInt()
        if (v != -1)
            return v
    } catch (e: ArrayIndexOutOfBoundsException) {

    }
    throw HexFormatException("$character is not a hexadecimal digit")
}

private val lowercasehex: Boolean = System.getProperty("ninja.blacknet.codec.base.hex.lowercase")?.toBoolean() ?: false

@Deprecated("")
fun hex(bytes: ByteArray, lowerCase: Boolean): String {
    val encodeTable = if (!lowerCase) HEX_CHARS else HEX_CHARS_LOWER

    val buffer = CharArray(bytes.size * 2)
    var bufferIndex = 0

    for (i in 0 until bytes.size) {
        val v = bytes[i].toInt()
        val firstIndex = (v and 0xF0).ushr(4)
        val secondIndex = v and 0x0F
        buffer[bufferIndex++] = encodeTable[firstIndex]
        buffer[bufferIndex++] = encodeTable[secondIndex]
    }

    return String(buffer)
}

/**
 * Returns the hex-string representation of this byte array.
 *
 * @return the encoded [String]
 */
@Deprecated("")
fun ByteArray.toHex(): String {
    return hex(this, lowercasehex)
}

/**
 * Returns the byte array representation of a hex-string.
 * @param string the hex-string
 * @param size expected size in bytes (optional)
 * @return the decoded [ByteArray]
 * @throws HexFormatException if the string is not a hexadecimal number
 */
@Deprecated("")
@Throws(HexFormatException::class)
fun fromHex(string: String, size: Int = 0): ByteArray {
    val length = string.length
    if (size == 0) {
        if (length % 2 == 1)
            throw HexFormatException("Odd length ${string.length}")
    } else {
        if (length != size * 2)
            throw HexFormatException("Expected length ${size * 2} actual ${string.length}")
    }

    val result = ByteArray(length / 2)
    var resultIndex = 0

    for (i in 0 until length step 2) {
        val firstIndex = decodeTable(string[i])
        val secondIndex = decodeTable(string[i + 1])

        val v = firstIndex.shl(4).or(secondIndex)
        result[resultIndex++] = v.toByte()
    }

    return result
}

/**
 * Thrown to indicate that the given string does not have the appropriate format.
 */
@Deprecated("")
class HexFormatException(message: String) : RuntimeException(message)
