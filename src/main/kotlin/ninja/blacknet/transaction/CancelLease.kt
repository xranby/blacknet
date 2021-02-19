/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.transaction

import kotlinx.serialization.Serializable
import ninja.blacknet.core.*
import ninja.blacknet.crypto.Address
import ninja.blacknet.crypto.PublicKeySerializer
import ninja.blacknet.serialization.LongSerializer

/**
 * 取消合約
 */
@Serializable
class CancelLease(
        @Serializable(with = LongSerializer::class)
        val amount: Long,
        @Serializable(with = PublicKeySerializer::class)
        val to: ByteArray,
        val height: Int
) : TxData {
    override fun processImpl(tx: Transaction, hash: ByteArray, dataIndex: Int, ledger: Ledger): Status {
        val toAccount = ledger.getAccount(to)
        if (toAccount == null) {
            return Invalid("Account not found")
        }
        if (toAccount.leases.remove(AccountState.Lease(tx.from, height, amount))) {
            ledger.setAccount(to, toAccount)
            val account = ledger.getAccount(tx.from)!!
            account.debit(ledger.height(), amount)
            ledger.setAccount(tx.from, account)
            return Accepted
        }
        return Invalid("Lease not found")
    }

    fun involves(publicKey: ByteArray) = to.contentEquals(publicKey)
}
