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
import kotlinx.serialization.Serializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonEncoder
import kotlinx.serialization.json.JsonPrimitive
import ninja.blacknet.crypto.HashSerializer
import ninja.blacknet.db.WalletDB
import ninja.blacknet.serialization.notSupportedFormatError

@Serializable
class WalletV1(val seq: Int, val transactions: ArrayList<JsonElement>) {
    constructor(wallet: WalletDB.Wallet) : this(wallet.seq, ArrayList(wallet.transactions.size)) {
        wallet.transactions.forEach { (hash, txData) ->
            transactions.add(JsonPrimitive(HashSerializer.encode(hash)))
            transactions.add(TransactionDataV1(txData).toJson())
        }
    }
}

@Serializable
class TransactionDataV1(
        val type: Byte,
        val time: Long,
        var height: Int
) {
    constructor(txData: WalletDB.TransactionData) : this(txData.types[0].type, txData.time, txData.height)
    fun toJson() = Json.toJson(serializer(), this)

    @Serializer(forClass = TransactionDataV1::class)
    companion object {
        override fun serialize(encoder: Encoder, value: TransactionDataV1) {
            when (encoder) {
                is JsonEncoder -> {
                    @Suppress("NAME_SHADOWING")
                    val encoder = encoder.beginStructure(descriptor)
                    encoder.encodeSerializableElement(descriptor, 0, Int.serializer(), value.type.toUByte().toInt())
                    encoder.encodeSerializableElement(descriptor, 1, Long.serializer(), value.time)
                    encoder.encodeSerializableElement(descriptor, 2, Int.serializer(), value.height)
                    encoder.endStructure(descriptor)
                }
                else -> throw notSupportedFormatError(encoder, this)
            }
        }
    }
}
