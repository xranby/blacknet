/*
 * Copyright (c) 2019-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.rpc.v2

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import ninja.blacknet.core.Block
import ninja.blacknet.core.Transaction
import ninja.blacknet.crypto.HashSerializer
import ninja.blacknet.crypto.PublicKeySerializer
import ninja.blacknet.crypto.SignatureSerializer
import ninja.blacknet.serialization.bbf.binaryFormat
import ninja.blacknet.serialization.json.json

@Serializable
class BlockInfo(
        @Serializable(with = HashSerializer::class)
        val hash: ByteArray,
        val size: Int,
        val version: Int,
        @Serializable(with = HashSerializer::class)
        val previous: ByteArray,
        val time: Long,
        @Serializable(with = PublicKeySerializer::class)
        val generator: ByteArray,
        @Serializable(with = HashSerializer::class)
        val contentHash: ByteArray,
        @Serializable(with = SignatureSerializer::class)
        var signature: ByteArray,
        val transactions: JsonElement
) {
    constructor(block: Block, hash: ByteArray, size: Int, txdetail: Boolean) : this(
            hash,
            size,
            block.version,
            block.previous,
            block.time,
            block.generator,
            block.contentHash,
            block.signature,
            transactions(block, txdetail)
    )

    companion object {
        private fun transactions(block: Block, txdetail: Boolean): JsonElement {
            if (txdetail) {
                return JsonArray(block.transactions.map { bytes ->
                    val tx = binaryFormat.decodeFromByteArray(Transaction.serializer(), bytes)
                    val txHash = Transaction.hash(bytes)
                    return@map json.encodeToJsonElement(TransactionInfo.serializer(), TransactionInfo(tx, txHash, bytes.size))
                })
            }
            return JsonPrimitive(block.transactions.size)
        }
    }
}
