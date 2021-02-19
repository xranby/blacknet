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
import ninja.blacknet.crypto.Address
import ninja.blacknet.crypto.PoS
import ninja.blacknet.crypto.PublicKeySerializer
import ninja.blacknet.serialization.LongSerializer

/**
 * 提款金額
 */
@Serializable
class WithdrawFromLease(
        @Serializable(with = LongSerializer::class)
        val withdraw: Long,
        @Serializable(with = LongSerializer::class)
        val amount: Long,
        @Serializable(with = PublicKeySerializer::class)
        val to: ByteArray,
        val height: Int
) : TxData {
    override fun processImpl(tx: Transaction, hash: ByteArray, dataIndex: Int, ledger: Ledger): Status {
        if (withdraw <= 0 || withdraw > amount) {
            return Invalid("Invalid withdraw amount")
        }
        if (withdraw > amount - PoS.MIN_LEASE) {
            return Invalid("Can not withdraw more than ${amount - PoS.MIN_LEASE}")
        }
        val toAccount = ledger.getAccount(to)
        if (toAccount == null) {
            return Invalid("Account not found")
        }
        val lease = toAccount.leases.find { it.publicKey.contentEquals(tx.from) && it.height == height && it.amount == amount }
        if (lease == null) {
            return Invalid("Lease not found")
        }
        lease.amount -= withdraw
        ledger.setAccount(to, toAccount)
        val account = ledger.getAccount(tx.from)!!
        account.debit(ledger.height(), withdraw)
        ledger.setAccount(tx.from, account)
        return Accepted
    }

    fun involves(publicKey: ByteArray) = to.contentEquals(publicKey)
}
