/*
 * Copyright (c) 2018 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.crypto

import kotlin.experimental.and

object Bech32 {
    private const val CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

    class Data(val hrp: ByteArray, val data: ByteArray)

    fun encode(bech32: Data): String {
        val converted = convertBits(bech32.data, 8, 5, true)!!

        val chk = createChecksum(bech32.hrp, converted)

        val ret = ByteArray(bech32.hrp.size + 1 + converted.size + chk.size)
        System.arraycopy(bech32.hrp, 0, ret, 0, bech32.hrp.size)
        ret[bech32.hrp.size] = 0x31
        for (i in 0 until converted.size) {
            ret[i + bech32.hrp.size + 1] = CHARSET[converted[i].toInt()].toByte()
        }
        for (i in 0 until chk.size) {
            ret[i + bech32.hrp.size + 1 + converted.size] = CHARSET[chk[i].toInt()].toByte()
        }

        return String(ret, Charsets.US_ASCII)
    }

    fun decode(bech: String): Data? {
        if (bech.length < 8 || bech.length > 90)
            return null

        var lower = false
        var upper = false
        var pos = -1

        for (i in bech.indices) {
            when (bech[i]) {
                !in '!'..'~' -> return null
                in 'a'..'z' -> lower = true
                in 'A'..'Z' -> upper = true
                '1' -> pos = i
            }
        }

        if (lower && upper)
            return null

        if (pos < 1) {
            return null
        } else if (pos + 7 > bech.length) {
            return null
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
                return null
            data[j] = b.toByte()
            i++
            j++
        }

        if (!verifyChecksum(hrp, data)) {
            return null
        }

        val ret = data.copyOf(data.size - 6)
        val converted = convertBits(ret, 5, 8, false) ?: return null

        return Data(hrp, converted)
    }

    private fun polymod(values: ByteArray): Int {
        val GENERATORS = intArrayOf(0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)

        var chk = 1

        for (b in values) {
            val top = (chk shr 0x19).toByte()
            chk = b.toInt() xor (chk and 0x1ffffff shl 5)
            for (i in 0..4) {
                chk = chk xor if (top.toInt() shr i and 1 == 1) GENERATORS[i] else 0
            }
        }

        return chk
    }

    private fun hrpExpand(hrp: ByteArray): ByteArray {
        val ret = ByteArray(hrp.size * 2 + 1)

        for (i in 0 until hrp.size) {
            ret[i] = hrp[i] shr 5
            ret[i + hrp.size + 1] = hrp[i] and 0x1f
        }
        ret[hrp.size] = 0

        return ret
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
        val ret = ByteArray(6)
        for (i in ret.indices) {
            ret[i] = (polymod shr 5 * (5 - i) and 0x1f).toByte()
        }

        return ret
    }

    private fun convertBits(data: ByteArray, fromBits: Int, toBits: Int, pad: Boolean): ByteArray? {
        var acc = 0
        var bits = 0
        val maxv = (1 shl toBits) - 1
        val ret = ArrayList<Byte>(32)

        for (value in data) {
            val b = value.toInt() and 0xff

            if (b < 0) {
                return null
            } else if (b shr fromBits > 0) {
                return null
            }

            acc = acc shl fromBits or b
            bits += fromBits
            while (bits >= toBits) {
                bits -= toBits
                ret.add((acc shr bits and maxv).toByte())
            }
        }

        if (pad && bits > 0) {
            ret.add((acc shl toBits - bits and maxv).toByte())
        } else if (bits >= fromBits || (acc shl toBits - bits and maxv).toByte().toInt() != 0) {
            return null
        }

        return ret.toByteArray()
    }

    private infix fun Byte.shr(other: Byte): Byte = (this.toInt() shr other.toInt()).toByte()
}
