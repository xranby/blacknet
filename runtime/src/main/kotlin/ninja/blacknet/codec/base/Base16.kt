/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.codec.base

import ninja.blacknet.codec.CodecException
import ninja.blacknet.codec.StringCodec

public object Base16 : StringCodec {
    @Throws(HexCodecException::class)
    override fun decode(string: String): ByteArray {
        val length = string.length
        if (length % 2 == 1)
            throw HexCodecException("Odd length ${string.length}")

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

    override fun encode(bytes: ByteArray): String {
        val encodeTable = HEX_CHARS

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

    private val HEX_CHARS = if (System.getProperty("ninja.blacknet.codec.base.hex.lowercase") == "true")
        charArrayOf('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f')
    else
        charArrayOf('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F')

    private val HEX_DECODE_TABLE = byteArrayOf(-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, -1, -1, -1, -1, -1, -1, -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 10, 11, 12, 13, 14, 15)

    private fun decodeTable(character: Char): Int {
        val index = character.toInt()
        try {
            val v = HEX_DECODE_TABLE[index].toInt()
            if (v != -1)
                return v
        } catch (e: ArrayIndexOutOfBoundsException) {

        }
        throw HexCodecException("$character is not a hexadecimal digit")
    }
}

public class HexCodecException(message: String) : CodecException(message)
