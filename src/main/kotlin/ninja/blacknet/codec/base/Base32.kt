/*
 * Copyright (c) 2019-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.codec.base

object Base32 {
    private const val CHARSET = "abcdefghijklmnopqrstuvwxyz234567"
    private val DECODE_TABLE = byteArrayOf(
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 26, 27, 28, 29, 30, 31, -1, -1, -1, -1,
            -1, -1, -1, -1, -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
            15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1,  0,  1,  2,
             3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
            23, 24, 25
    )

    fun encode(bytes: ByteArray, pad: Boolean = false): String {
        val converted = Bech32.convertBits(bytes, 8, 5, true)

        val builder = StringBuilder(converted.size)
        for (byte in converted)
            builder.append(CHARSET[byte.toInt()])

        if (pad)
            while (builder.length % 8 != 0)
                builder.append('=')

        return builder.toString()
    }

    fun decode(string: String): ByteArray? {
        val base = string.takeWhile { it != '=' }
        val bytes = ByteArray(base.length)

        for (i in base.indices) {
            val x = base[i].toInt()
            val byte = if (x >= 0 && x < DECODE_TABLE.size)
                DECODE_TABLE[x]
            else
                return null

            if (byte != (-1).toByte())
                bytes[i] = byte
            else
                return null
        }

        return try {
            Bech32.convertBits(bytes, 5, 8, false)
        } catch (e: Throwable) {
            null
        }
    }
}
