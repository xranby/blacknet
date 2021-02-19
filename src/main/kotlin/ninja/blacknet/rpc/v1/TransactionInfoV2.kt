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

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.buildJsonObject
import ninja.blacknet.core.Transaction
import ninja.blacknet.crypto.Address
import ninja.blacknet.crypto.HashSerializer
import ninja.blacknet.crypto.SignatureSerializer
import ninja.blacknet.serialization.bbf.binaryFormat
import ninja.blacknet.transaction.TxData
import ninja.blacknet.transaction.TxType

@Serializable
class TransactionInfoV2(
        val hash: String,
        val size: Int,
        val signature: String,
        val from: String,
        val seq: Int,
        val blockHash: String,
        val fee: String,
        val type: Int,
        val data: JsonElement
) {
    constructor(tx: Transaction, hash: ByteArray, size: Int) : this(
            HashSerializer.encode(hash),
            size,
            SignatureSerializer.encode(tx.signature),
            Address.encode(tx.from),
            tx.seq,
            HashSerializer.encode(tx.referenceChain),
            tx.fee.toString(),
            tx.type.toUByte().toInt(),
            data(tx.type, tx.data)
    )

    fun toJson() = Json.toJson(serializer(), this)

    companion object {
        fun data(type: Byte, bytes: ByteArray): JsonElement {
            if (type == TxType.Generated.type) return buildJsonObject {}
            @Suppress("UNCHECKED_CAST")
            val serializer = TxType.getSerializer(type) as KSerializer<TxData>
            val txData = binaryFormat.decodeFromByteArray(serializer, bytes)
            return Json.toJson(serializer, txData)
        }
    }
}
