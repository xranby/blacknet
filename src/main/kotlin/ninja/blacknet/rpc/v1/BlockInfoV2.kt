/*
 * Copyright (c) 2019-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

@file:Suppress("DEPRECATION")

package ninja.blacknet.rpc.v1

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import ninja.blacknet.core.Block
import ninja.blacknet.core.Transaction
import ninja.blacknet.crypto.Address
import ninja.blacknet.crypto.HashSerializer
import ninja.blacknet.crypto.SignatureSerializer
import ninja.blacknet.serialization.bbf.binaryFormat

@Serializable
class BlockInfoV2(
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
    constructor(block: Block, hash: ByteArray, size: Int, txdetail: Boolean) : this(
            HashSerializer.encode(hash),
            size,
            block.version,
            HashSerializer.encode(block.previous),
            block.time,
            Address.encode(block.generator),
            HashSerializer.encode(block.contentHash),
            SignatureSerializer.encode(block.signature),
            transactions(block, txdetail)
    )

    fun toJson() = Json.toJson(serializer(), this)

    companion object {
        private fun transactions(block: Block, txdetail: Boolean): JsonElement {
            if (txdetail) {
                return JsonArray(block.transactions.map {
                    val bytes = it
                    val tx = binaryFormat.decodeFromByteArray(Transaction.serializer(), bytes)
                    val txHash = Transaction.hash(bytes)
                    return@map TransactionInfoV2(tx, txHash, bytes.size).toJson()
                })
            }
            return JsonPrimitive(block.transactions.size)
        }
    }
}
