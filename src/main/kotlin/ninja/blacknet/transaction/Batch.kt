/*
 * Copyright (c) 2019-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.transaction

import kotlinx.serialization.Serializable
import ninja.blacknet.core.*
import ninja.blacknet.serialization.bbf.binaryFormat
import ninja.blacknet.serialization.ByteArraySerializer

/**
 * 批次處理
 */
@Serializable
class Batch(
        val multiData: ArrayList<TxDataData>
) : TxData {
    @Serializable
    class TxDataData(
            val type: Byte,
            @Serializable(with = ByteArraySerializer::class)
            val data: ByteArray
    ) {
        operator fun component1() = type
        operator fun component2() = data
    }

    override fun processImpl(tx: Transaction, hash: ByteArray, dataIndex: Int, ledger: Ledger): Status {
        if (dataIndex != 0) {
            return Invalid("Batch is not permitted to contain Batch")
        }
        if (multiData.size < 2 || multiData.size > 20) {
            return Invalid("Invalid Batch size ${multiData.size}")
        }

        for (index in 0 until multiData.size) {
            val (type, bytes) = multiData[index]
            val serializer = TxType.getSerializer(type)
            val data = binaryFormat.decodeFromByteArray(serializer, bytes)
            val status = data.processImpl(tx, hash, index + 1, ledger)
            if (status != Accepted) {
                return notAccepted("Batch ${index + 1}", status)
            }
        }

        return Accepted
    }
}
