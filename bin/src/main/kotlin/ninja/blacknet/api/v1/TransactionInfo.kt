/*
 * Copyright (c) 2019 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.api.v1

import kotlinx.serialization.Serializable
import ninja.blacknet.core.Transaction
import ninja.blacknet.crypto.Address
import ninja.blacknet.crypto.Hash
import ninja.blacknet.serialization.Json
import ninja.blacknet.transaction.*

@Serializable
class TransactionInfo(
        val hash: String,
        val size: Int,
        val signature: String,
        val from: String,
        val seq: Int,
        val blockHash: String,
        val fee: Long,
        val type: Int,
        val data: String
) {
    constructor(tx: Transaction, hash: Hash, size: Int) : this(
            hash.toString(),
            size,
            tx.signature.toString(),
            Address.encode(tx.from),
            tx.seq,
            tx.blockHash.toString(),
            tx.fee,
            tx.type.toUByte().toInt(),
            data(tx.type, tx.data.array)
    )

    companion object {
        fun fromBytes(bytes: ByteArray): TransactionInfo? {
            val hash = Transaction.Hasher(bytes)
            return Transaction.deserialize(bytes)?.let { TransactionInfo(it, hash, bytes.size) }
        }

        private fun data(type: Byte, bytes: ByteArray): String {
            val txData = TxData.deserialize(type, bytes) ?: return "Deserialization error"
            return when (type) {
                TxType.Transfer.type -> Json.stringify(TransferInfo.serializer(), TransferInfo(txData as Transfer))
                TxType.Burn.type -> Json.stringify(Burn.serializer(), txData as Burn)
                TxType.Lease.type -> Json.stringify(Lease.serializer(), txData as Lease)
                TxType.CancelLease.type -> Json.stringify(CancelLease.serializer(), txData as CancelLease)
                TxType.Bundle.type -> Json.stringify(Bundle.serializer(), txData as Bundle)
                else -> "Unknown type:$type data:$bytes"
            }
        }
    }
}
