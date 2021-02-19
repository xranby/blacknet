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
import ninja.blacknet.contract.HashTimeLockContractIdSerializer
import ninja.blacknet.core.*
import ninja.blacknet.crypto.Address

/**
 * 償還合約
 */
@Serializable
class RefundHTLC(
        @Serializable(with = HashTimeLockContractIdSerializer::class)
        val id: ByteArray
) : TxData {
    override fun processImpl(tx: Transaction, hash: ByteArray, dataIndex: Int, ledger: Ledger): Status {
        val htlc = ledger.getHTLC(id)
        if (htlc == null) {
            return Invalid("HTLC not found")
        }
        if (!tx.from.contentEquals(htlc.from)) {
            return Invalid("Invalid sender")
        }
        if (!htlc.timeLock.verify(htlc.height, htlc.time, ledger.height(), ledger.blockTime())) {
            return Invalid("Invalid time lock")
        }

        val account = ledger.getAccount(tx.from)!!
        account.debit(ledger.height(), htlc.amount)
        ledger.setAccount(tx.from, account)
        ledger.removeHTLC(id)
        return Accepted
    }

    fun involves(ids: Set<ByteArray>) = ids.contains(id)
}
