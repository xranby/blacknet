/*
 * Copyright (c) 2018 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.crypto

import com.google.common.primitives.Ints
import com.google.common.primitives.Longs
import com.rfksystems.blake2b.Blake2b
import kotlinx.serialization.toUtf8Bytes

object Blake2b : (ByteArray) -> ByteArray {
    fun hash(message: ByteArray): Hash {
        val bytes = ByteArray(Hash.SIZE)
        val b = Blake2b(Hash.DIGEST_SIZE)
        b.update(message, 0, message.size)
        b.digest(bytes, 0)
        return Hash(bytes)
    }

    fun hash(message: ByteArray, offset: Int, len: Int): Hash {
        val bytes = ByteArray(Hash.SIZE)
        val b = Blake2b(Hash.DIGEST_SIZE)
        b.update(message, offset, len)
        b.digest(bytes, 0)
        return Hash(bytes)
    }

    fun hash(digestSize: Int, message: ByteArray): ByteArray {
        val bytes = ByteArray(digestSize / 8)
        val b = Blake2b(digestSize)
        b.update(message, 0, message.size)
        b.digest(bytes, 0)
        return bytes
    }

    fun utf8(string: String): Hash {
        return hash(string.toUtf8Bytes())
    }

    class Hasher(private val blake2b: Blake2b = Blake2b(Hash.DIGEST_SIZE)) {
        operator fun plus(int: Int): Hasher {
            return this.plus(Ints.toByteArray(int))
        }

        operator fun plus(long: Long): Hasher {
            return this.plus(Longs.toByteArray(long))
        }

        operator fun plus(string: String): Hasher {
            return this.plus(string.toUtf8Bytes())
        }

        operator fun plus(bytes: ByteArray): Hasher {
            blake2b.update(bytes, 0, bytes.size)
            return this
        }

        fun hash(): Hash {
            val bytes = ByteArray(Hash.SIZE)
            blake2b.digest(bytes, 0)
            return Hash(bytes)
        }
    }

    override fun invoke(bytes: ByteArray): ByteArray = hash(bytes).bytes
}
