/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

@file:Suppress("DEPRECATION")

package ninja.blacknet.rpc.v1

import kotlinx.serialization.Serializable
import ninja.blacknet.core.Block
import ninja.blacknet.core.Transaction
import ninja.blacknet.crypto.Address
import ninja.blacknet.crypto.HashSerializer
import ninja.blacknet.crypto.SignatureSerializer
import ninja.blacknet.db.BlockDB

@Serializable
class BlockInfoV1(
        val size: Int,
        val version: Int,
        val previous: String,
        val time: Long,
        val generator: String,
        val contentHash: String,
        val signature: String,
        val transactions: List<String>
) {
    constructor(block: Block, size: Int, txdetail: Boolean) : this(
            size,
            block.version,
            HashSerializer.encode(block.previous),
            block.time,
            Address.encode(block.generator),
            HashSerializer.encode(block.contentHash),
            SignatureSerializer.encode(block.signature),
            block.transactions.map {
                if (txdetail)
                    Json.stringify(TransactionInfoV1.serializer(), TransactionInfoV1.fromBytes(it))
                else
                    HashSerializer.encode(Transaction.hash(it))
            }
    )

    companion object {
        suspend fun get(hash: ByteArray, txdetail: Boolean): BlockInfoV1? {
            val block = BlockDB.block(hash) ?: return null
            return BlockInfoV1(block.first, block.second, txdetail)
        }
    }
}
