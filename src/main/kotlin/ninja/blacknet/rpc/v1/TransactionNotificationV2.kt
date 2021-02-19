/*
 * Copyright (c) 2019-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.rpc.v1

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import ninja.blacknet.core.Transaction
import ninja.blacknet.crypto.Address
import ninja.blacknet.crypto.HashSerializer
import ninja.blacknet.crypto.SignatureSerializer

@Serializable
class TransactionNotificationV2(
        val hash: String,
        val time: Long,
        val size: Int,
        val signature: String,
        val from: String,
        val seq: Int,
        val blockHash: String,
        val fee: String,
        val type: Int,
        val data: JsonElement
) {
    constructor(tx: Transaction, hash: ByteArray, time: Long, size: Int) : this(
            HashSerializer.encode(hash),
            time,
            size,
            SignatureSerializer.encode(tx.signature),
            Address.encode(tx.from),
            tx.seq,
            HashSerializer.encode(tx.referenceChain),
            tx.fee.toString(),
            tx.type.toUByte().toInt(),
            TransactionInfoV2.data(tx.type, tx.data)
    )
}
