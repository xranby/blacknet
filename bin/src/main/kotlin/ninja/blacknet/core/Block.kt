/*
 * Copyright (c) 2018 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.core

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonLiteral
import ninja.blacknet.crypto.*
import ninja.blacknet.serialization.BinaryDecoder
import ninja.blacknet.serialization.BinaryEncoder
import ninja.blacknet.serialization.Json
import ninja.blacknet.serialization.SerializableByteArray

@Serializable
class Block(
        val version: Int,
        val previous: Hash,
        val time: Long,
        val generator: PublicKey,
        var contentHash: Hash,
        var signature: Signature,
        val transactions: ArrayList<SerializableByteArray>
) {
    fun serialize(): ByteArray = BinaryEncoder.toBytes(serializer(), this)
    fun toJson(hash: Hash, size: Int, txdetail: Boolean) = Json.toJson(Info.serializer(), Info(this, hash, size, txdetail))

    fun sign(privateKey: PrivateKey): Pair<Hash, ByteArray> {
        val bytes = serialize()
        contentHash = contentHash(bytes)
        System.arraycopy(contentHash.bytes, 0, bytes, CONTENT_HASH_POS, Hash.SIZE)
        val hash = Hasher(bytes)
        signature = Ed25519.sign(hash, privateKey)
        System.arraycopy(signature.bytes, 0, bytes, SIGNATURE_POS, Signature.SIZE)
        return Pair(hash, bytes)
    }

    fun verifyContentHash(bytes: ByteArray): Boolean {
        return contentHash == contentHash(bytes)
    }

    fun verifySignature(hash: Hash): Boolean {
        return Ed25519.verify(signature, hash, generator)
    }

    private fun contentHash(bytes: ByteArray): Hash {
        return Blake2b.hash(bytes, HEADER_SIZE, bytes.size - HEADER_SIZE)
    }

    object Hasher : (ByteArray) -> Hash {
        override fun invoke(bytes: ByteArray): Hash {
            return Blake2b.hash(bytes, 0, HEADER_SIZE - Signature.SIZE)
        }
    }

    companion object {
        const val VERSION = 1
        const val CONTENT_HASH_POS = 4 + Hash.SIZE + 8 + PublicKey.SIZE
        const val SIGNATURE_POS = CONTENT_HASH_POS + Hash.SIZE
        const val HEADER_SIZE = SIGNATURE_POS + Signature.SIZE

        fun deserialize(bytes: ByteArray): Block? = BinaryDecoder.fromBytes(bytes).decode(serializer())

        fun create(previous: Hash, time: Long, generator: PublicKey): Block {
            return Block(VERSION, previous, time, generator, Hash.ZERO, Signature.EMPTY, ArrayList())
        }
    }

    @Suppress("unused")
    @Serializable
    class Info(
            val hash: String,
            val size: Int,
            val version: Int,
            val previous: String,
            val time: Long,
            val generator: String,
            val contentHash: String,
            val signature: String,
            val transactions: JsonElement
    ) {
        constructor(block: Block, hash: Hash, size: Int, txdetail: Boolean) : this(
                hash.toString(),
                size,
                block.version,
                block.previous.toString(),
                block.time,
                Address.encode(block.generator),
                block.contentHash.toString(),
                block.signature.toString(),
                transactions(block, txdetail)
        )

        companion object {
            private fun transactions(block: Block, txdetail: Boolean): JsonElement {
                if (txdetail) {
                    return JsonArray(block.transactions.map {
                        val bytes = it.array
                        val tx = Transaction.deserialize(bytes) ?: throw RuntimeException("Deserialization error")
                        val txHash = Transaction.Hasher(bytes)
                        return@map tx.toJson(txHash, bytes.size)
                    })
                }
                return JsonLiteral(block.transactions.size)
            }
        }
    }
}
