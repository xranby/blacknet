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
import ninja.blacknet.serialization.LongSerializer
import ninja.blacknet.transaction.TxData
import ninja.blacknet.transaction.TxType
import ninja.blacknet.util.emptyByteArray

@Serializable
class Transaction(
        @Serializable(with = SignatureSerializer::class)
        var signature: ByteArray,
        @Serializable(with = PublicKeySerializer::class)
        val from: ByteArray,
        val seq: Int,
        @Serializable(with = HashSerializer::class)
        val referenceChain: ByteArray,
        @Serializable(with = LongSerializer::class)
        val fee: Long,
        val type: Byte,
        @Serializable(with = ByteArraySerializer::class)
        val data: ByteArray
) {
    fun data(): TxData {
        val serializer = TxType.getSerializer(type)
        return binaryFormat.decodeFromByteArray(serializer, data)
    }

    fun sign(privateKey: ByteArray): Pair<ByteArray, ByteArray> {
        val bytes = binaryFormat.encodeToByteArray(serializer(), this)
        val hash = hash(bytes)
        signature = Ed25519.sign(hash, privateKey)
        System.arraycopy(signature, 0, bytes, 0, SignatureSerializer.SIZE_BYTES)
        return Pair(hash, bytes)
    }

    fun verifySignature(hash: ByteArray): Boolean {
        return Ed25519.verify(signature, hash, from)
    }

    companion object {
        fun hash(bytes: ByteArray): ByteArray {
            return buildHash {
                encodeByteArray(bytes, SignatureSerializer.SIZE_BYTES, bytes.size - SignatureSerializer.SIZE_BYTES)
            }
        }

        fun create(from: ByteArray, seq: Int, referenceChain: ByteArray, fee: Long, type: Byte, data: ByteArray): Transaction {
            return Transaction(SignatureSerializer.EMPTY, from, seq, referenceChain, fee, type, data)
        }

        /**
         * Returns a new transaction of the [TxType.Generated].
         *
         * [Transaction.signature] the empty signature
         *
         * [Transaction.from] generator of the block
         *
         * [Transaction.seq] height of the block
         *
         * [Transaction.referenceChain] hash of the block
         *
         * [Transaction.fee] the amount
         *
         * [Transaction.type] 254
         *
         * [Transaction.data] the empty object
         *
         * @return the constructed [Transaction]
         */
        fun generated(from: ByteArray, height: Int, referenceChain: ByteArray, amount: Long): Transaction {
            return Transaction(SignatureSerializer.EMPTY, from, height, referenceChain, amount, TxType.Generated.type, emptyByteArray())
        }
    }
}
