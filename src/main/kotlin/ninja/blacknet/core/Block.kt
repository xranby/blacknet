/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.core

import kotlinx.serialization.Serializable
import ninja.blacknet.crypto.*
import ninja.blacknet.crypto.Blake2b.buildHash
import ninja.blacknet.serialization.bbf.binaryFormat
import ninja.blacknet.serialization.ByteArraySerializer

@Serializable
class Block(
        val version: Int,
        @Serializable(with = HashSerializer::class)
        val previous: ByteArray,
        val time: Long,
        @Serializable(with = PublicKeySerializer::class)
        val generator: ByteArray,
        @Serializable(with = HashSerializer::class)
        var contentHash: ByteArray,
        @Serializable(with = SignatureSerializer::class)
        var signature: ByteArray,
        val transactions: ArrayList<@Serializable(ByteArraySerializer::class) ByteArray>
) {
    fun sign(privateKey: ByteArray): Pair<ByteArray, ByteArray> {
        val bytes = binaryFormat.encodeToByteArray(serializer(), this)
        contentHash = contentHash(bytes)
        System.arraycopy(contentHash, 0, bytes, CONTENT_HASH_POS, HashSerializer.SIZE_BYTES)
        val hash = hash(bytes)
        signature = Ed25519.sign(hash, privateKey)
        System.arraycopy(signature, 0, bytes, SIGNATURE_POS, SignatureSerializer.SIZE_BYTES)
        return Pair(hash, bytes)
    }

    fun verifyContentHash(bytes: ByteArray): Boolean {
        return contentHash.contentEquals(contentHash(bytes))
    }

    fun verifySignature(hash: ByteArray): Boolean {
        return Ed25519.verify(signature, hash, generator)
    }

    private fun contentHash(bytes: ByteArray): ByteArray {
        return buildHash {
            encodeByteArray(bytes, HEADER_SIZE_BYTES, bytes.size - HEADER_SIZE_BYTES)
        }
    }

    companion object {
        const val VERSION = 2
        const val CONTENT_HASH_POS = Int.SIZE_BYTES + HashSerializer.SIZE_BYTES + Long.SIZE_BYTES + PublicKeySerializer.SIZE_BYTES
        const val SIGNATURE_POS = CONTENT_HASH_POS + HashSerializer.SIZE_BYTES
        const val HEADER_SIZE_BYTES = SIGNATURE_POS + SignatureSerializer.SIZE_BYTES

        fun hash(bytes: ByteArray): ByteArray {
            return buildHash {
                encodeByteArray(bytes, 0, HEADER_SIZE_BYTES - SignatureSerializer.SIZE_BYTES)
            }
        }

        fun create(previous: ByteArray, time: Long, generator: ByteArray): Block {
            return Block(VERSION, previous, time, generator, HashSerializer.ZERO, SignatureSerializer.EMPTY, ArrayList())
        }
    }
}
