/*
 * Copyright (c) 2018 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.crypto

import java.security.SecureRandom

object Mnemonic {
    private const val WORDS = 12
    private val random = SecureRandom()

    fun generate(): Pair<String, PrivateKey> {
        val builder = StringBuilder(108)

        while (true) {
            for (i in 1..WORDS) {
                val rnd = random.nextInt(Bip39.ENGLISH.size)
                builder.append(Bip39.ENGLISH[rnd])
                if (i < WORDS) builder.append(' ')
            }

            val mnemonic = builder.toString()
            val hash = hash(mnemonic)
            if (checkVersion(hash.bytes))
                return Pair(mnemonic, PrivateKey(hash.bytes))

            builder.setLength(0)
        }
    }

    fun fromString(string: String?): PrivateKey? {
        if (string == null)
            return null
        val hash = hash(string)
        if (checkVersion(hash.bytes))
            return PrivateKey(hash.bytes)
        return null
    }

    private fun checkVersion(bytes: ByteArray): Boolean {
        return bytes[0].toInt() and 0xF0 == 0x10
    }

    private fun hash(string: String): Hash {
        return Blake2b.utf8(string)
    }
}
