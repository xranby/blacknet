/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.codec.base

import kotlin.experimental.and

/**
 * Bech32 address format.
 *
 * Bitcoin improvement proposal 173 "Base32 address format for native v0-16 witness outputs"
 */
object Bech32 {
    private const val CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

    fun encode(hrp: ByteArray, data: ByteArray): String {
        val checksum = createChecksum(hrp, data)

        val result = ByteArray(hrp.size + 1 + data.size + checksum.size)
        System.arraycopy(hrp, 0, result, 0, hrp.size)
        result[hrp.size] = 0x31
        for (i in 0 until data.size) {
            result[i + hrp.size + 1] = CHARSET[data[i].toInt()].toByte()
        }
        for (i in 0 until checksum.size) {
            result[i + hrp.size + 1 + data.size] = CHARSET[checksum[i].toInt()].toByte()
        }

        return String(result, Charsets.US_ASCII)
    }

    fun decode(bech: String): Pair<ByteArray, ByteArray> {
        if (bech.length < 8 || bech.length > 90)
            throw Exception()

        var lower = false
        var upper = false
        var pos = -1

        for (i in bech.indices) {
            when (bech[i]) {
                !in '!'..'~' -> throw Exception()
                in 'a'..'z' -> lower = true
                in 'A'..'Z' -> upper = true
                '1' -> pos = i
            }
        }

        if (lower && upper)
            throw Exception()

        if (pos < 1) {
            throw Exception()
        } else if (pos + 7 > bech.length) {
            throw Exception()
        }

        val bechLow = when (upper) {
            true -> bech.toLowerCase()
            false -> bech
        }

        val hrp = bechLow.substring(0, pos).toByteArray(Charsets.US_ASCII)

        val data = ByteArray(bechLow.length - pos - 1)
        var j = 0
        var i = pos + 1
        while (i < bechLow.length) {
            val b = CHARSET.indexOf(bechLow[i])
            if (b == -1)
                throw Exception()
            data[j] = b.toByte()
            i += 1
            j += 1
        }

        if (!verifyChecksum(hrp, data)) {
            throw Exception()
        }

        return Pair(hrp, data.copyOf(data.size - 6))
    }

    private fun polymod(values: ByteArray): Int {
        val GENERATORS = intArrayOf(0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)

        var checksum = 1

        for (b in values) {
            val top = (checksum shr 0x19).toByte()
            checksum = b.toInt() xor (checksum and 0x1ffffff shl 5)
            for (i in 0..4) {
                checksum = checksum xor if (top.toInt() shr i and 1 == 1) GENERATORS[i] else 0
            }
        }

        return checksum
    }

    private fun hrpExpand(hrp: ByteArray): ByteArray {
        val result = ByteArray(hrp.size * 2 + 1)

        for (i in 0 until hrp.size) {
            result[i] = hrp[i] shr 5
            result[i + hrp.size + 1] = hrp[i] and 0x1f
        }
        result[hrp.size] = 0

        return result
    }

    private fun verifyChecksum(hrp: ByteArray, data: ByteArray): Boolean {
        val exp = hrpExpand(hrp)

        val values = ByteArray(exp.size + data.size)
        System.arraycopy(exp, 0, values, 0, exp.size)
        System.arraycopy(data, 0, values, exp.size, data.size)

        return 1 == polymod(values)
    }

    private fun createChecksum(hrp: ByteArray, data: ByteArray): ByteArray {
        val zeroBytes = 6
        val expanded = hrpExpand(hrp)
        val values = ByteArray(expanded.size + data.size + zeroBytes)

        System.arraycopy(expanded, 0, values, 0, expanded.size)
        System.arraycopy(data, 0, values, expanded.size, data.size)

        val polymod = polymod(values) xor 1
        val result = ByteArray(6)
        for (i in result.indices) {
            result[i] = (polymod shr 5 * (5 - i) and 0x1f).toByte()
        }

        return result
    }

    fun convertBits(data: ByteArray, fromBits: Int, toBits: Int, pad: Boolean): ByteArray {
        var acc = 0
        var bits = 0
        val maxv = (1 shl toBits) - 1
        val result = ArrayList<Byte>(64)

        for (value in data) {
            val b = value.toInt() and 0xff

            if (b < 0) {
                throw Exception()
            } else if (b shr fromBits > 0) {
                throw Exception()
            }

            acc = acc shl fromBits or b
            bits += fromBits
            while (bits >= toBits) {
                bits -= toBits
                result.add((acc shr bits and maxv).toByte())
            }
        }

        if (pad && bits > 0) {
            result.add((acc shl toBits - bits and maxv).toByte())
        } else if (bits >= fromBits || (acc shl toBits - bits and maxv).toByte().toInt() != 0) {
            throw Exception()
        }

        return result.toByteArray()
    }

    private infix fun Byte.shr(other: Byte): Byte = (this.toInt() shr other.toInt()).toByte()
    @Suppress("RemoveEmptyPrimaryConstructor")
    private class Exception constructor() : RuntimeException("")
}
