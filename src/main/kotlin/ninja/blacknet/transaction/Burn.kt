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
import ninja.blacknet.serialization.ByteArraySerializer
import ninja.blacknet.serialization.LongSerializer

@Serializable
class Burn(
        @Serializable(with = LongSerializer::class)
        val amount: Long,
        @Serializable(with = ByteArraySerializer::class)
        val message: ByteArray
) : TxData {
    override fun processImpl(tx: Transaction, hash: ByteArray, dataIndex: Int, ledger: Ledger): Status {
        if (amount == 0L) {
            return Invalid("Invalid amount")
        }
        val account = ledger.getAccount(tx.from)!!
        val status = account.credit(amount)
        if (status != Accepted) {
            return status
        }
        ledger.setAccount(tx.from, account)
        ledger.addSupply(-amount)
        return Accepted
    }
}
