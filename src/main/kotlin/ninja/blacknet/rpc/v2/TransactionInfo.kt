/*
 * Copyright (c) 2019-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.rpc.v2

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import ninja.blacknet.core.Transaction
import ninja.blacknet.crypto.HashSerializer
import ninja.blacknet.crypto.PublicKeySerializer
import ninja.blacknet.crypto.SignatureSerializer
import ninja.blacknet.db.WalletDB
import ninja.blacknet.serialization.bbf.binaryFormat
import ninja.blacknet.serialization.json.json
import ninja.blacknet.serialization.LongSerializer
import ninja.blacknet.transaction.Batch
import ninja.blacknet.transaction.TxData
import ninja.blacknet.transaction.TxType

@Serializable
class TransactionInfo(
        @Serializable(with = HashSerializer::class)
        val hash: ByteArray,
        val size: Int,
        @Serializable(with = SignatureSerializer::class)
        val signature: ByteArray,
        @Serializable(with = PublicKeySerializer::class)
        val from: ByteArray,
        val seq: Int,
        @Serializable(with = HashSerializer::class)
        val referenceChain: ByteArray,
        @Serializable(with = LongSerializer::class)
        val fee: Long,
        val data: List<DataInfo>
) {
    constructor(tx: Transaction, hash: ByteArray, size: Int, filter: List<WalletDB.TransactionDataType>? = null) : this(
            hash,
            size,
            tx.signature,
            tx.from,
            tx.seq,
            tx.referenceChain,
            tx.fee,
            data(tx.type, tx.data, filter)
    )

    @Serializable
    class DataInfo(
            val type: Int,
            val dataIndex: Int,
            val data: JsonElement
    )

    companion object {
        fun data(type: Byte, bytes: ByteArray, filter: List<WalletDB.TransactionDataType>?): List<DataInfo> {
            val data = if (type == TxType.Generated.type) {
                listOf(DataInfo(type.toUByte().toInt(), 0, JsonObject(emptyMap())))
            } else if (type != TxType.Batch.type) {
                @Suppress("UNCHECKED_CAST")
                val serializer = TxType.getSerializer(type) as KSerializer<TxData>
                val data = binaryFormat.decodeFromByteArray(serializer, bytes)
                listOf(DataInfo(type.toUByte().toInt(), 0, json.encodeToJsonElement(serializer, data)))
            } else {
                val multiData = binaryFormat.decodeFromByteArray(Batch.serializer(), bytes)
                val list = ArrayList<DataInfo>(multiData.multiData.size)
                if (filter == null) {
                    for (index in 0 until multiData.multiData.size) {
                        val (dataType, dataBytes) = multiData.multiData[index]
                        @Suppress("UNCHECKED_CAST")
                        val serializer = TxType.getSerializer(dataType) as KSerializer<TxData>
                        val data = binaryFormat.decodeFromByteArray(serializer, dataBytes)
                        list.add(DataInfo(dataType.toUByte().toInt(), index + 1, json.encodeToJsonElement(serializer, data)))
                    }
                } else {
                    for (i in 0 until filter.size) {
                        val dataIndex = filter[i].dataIndex.toInt()
                        val (dataType, dataBytes) = multiData.multiData[dataIndex - 1]
                        @Suppress("UNCHECKED_CAST")
                        val serializer = TxType.getSerializer(dataType) as KSerializer<TxData>
                        val data = binaryFormat.decodeFromByteArray(serializer, dataBytes)
                        list.add(DataInfo(dataType.toUByte().toInt(), dataIndex, json.encodeToJsonElement(serializer, data)))
                    }
                }
                list
            }
            return data
        }
    }
}
