/*
 * Copyright (c) 2019-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.codec.base

object Base64 {
    private const val CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    private const val CHARSET_I2P = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~"
    private val DECODE_TABLE = byteArrayOf(
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, 62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1,
            -1, -1, -1, -1, -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
            15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
            29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
            49, 50, 51
    )
    private val DECODE_TABLE_I2P = byteArrayOf(
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, 62, -1, -1, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1,
            -1, -1, -1, -1, -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
            15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
            29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
            49, 50, 51, -1, -1, -1, 63
    )

    fun encode(bytes: ByteArray, i2p: Boolean = false): String {
        val converted = Bech32.convertBits(bytes, 8, 6, true)

        val builder = StringBuilder(converted.size)
        val charset = if (!i2p) CHARSET else CHARSET_I2P
        for (byte in converted)
            builder.append(charset[byte.toInt()])

        while (builder.length % 4 != 0)
            builder.append('=')

        return builder.toString()
    }

    fun decode(string: String, i2p: Boolean = false): ByteArray? {
        val base = string.takeWhile { it != '=' }
        val bytes = ByteArray(base.length)
        val table = if (!i2p) DECODE_TABLE else DECODE_TABLE_I2P

        for (i in base.indices) {
            val x = base[i].toInt()
            val byte = if (x >= 0 && x < table.size)
                table[x]
            else
                return null

            if (byte != (-1).toByte())
                bytes[i] = byte
            else
                return null
        }

        return try {
            Bech32.convertBits(bytes, 6, 8, false)
        } catch (e: Throwable) {
            null
        }
    }
}
