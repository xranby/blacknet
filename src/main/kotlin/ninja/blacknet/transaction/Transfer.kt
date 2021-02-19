/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.transaction

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import ninja.blacknet.core.*
import ninja.blacknet.crypto.Address
import ninja.blacknet.crypto.PaymentId
import ninja.blacknet.crypto.PublicKeySerializer
import ninja.blacknet.serialization.LongSerializer

@Serializable
class Transfer(
        @Serializable(with = LongSerializer::class)
        val amount: Long,
        @Serializable(with = PublicKeySerializer::class)
        val to: ByteArray,
        @SerialName("message")
        val paymentId: PaymentId
) : TxData {
    override fun processImpl(tx: Transaction, hash: ByteArray, dataIndex: Int, ledger: Ledger): Status {
        val account = ledger.getAccount(tx.from)!!
        val status = account.credit(amount)
        if (status != Accepted) {
            return status
        }
        ledger.setAccount(tx.from, account)
        val toAccount = ledger.getOrCreate(to)
        toAccount.debit(ledger.height(), amount)
        ledger.setAccount(to, toAccount)
        return Accepted
    }

    fun involves(publicKey: ByteArray) = to.contentEquals(publicKey)
}
