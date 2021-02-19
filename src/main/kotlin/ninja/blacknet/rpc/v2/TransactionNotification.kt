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
import ninja.blacknet.core.Transaction
import ninja.blacknet.crypto.Address
import ninja.blacknet.crypto.HashSerializer
import ninja.blacknet.crypto.SignatureSerializer
import ninja.blacknet.db.WalletDB

@Serializable
class TransactionNotification(
        val hash: String,
        val time: Long,
        val size: Int,
        val signature: String,
        val from: String,
        val seq: Int,
        val referenceChain: String,
        val fee: String,
        val type: Int,
        val data: List<TransactionInfo.DataInfo>
) {
    constructor(tx: Transaction, hash: ByteArray, time: Long, size: Int, filter: List<WalletDB.TransactionDataType>? = null) : this(
            HashSerializer.encode(hash),
            time,
            size,
            SignatureSerializer.encode(tx.signature),
            Address.encode(tx.from),
            tx.seq,
            HashSerializer.encode(tx.referenceChain),
            tx.fee.toString(),
            tx.type.toUByte().toInt(),
            TransactionInfo.data(tx.type, tx.data, filter)
    )
}
