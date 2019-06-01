/*
 * Copyright (c) 2018 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.transaction

import kotlinx.serialization.Serializable
import mu.KotlinLogging
import ninja.blacknet.core.*
import ninja.blacknet.crypto.Address
import ninja.blacknet.crypto.Hash
import ninja.blacknet.crypto.PublicKey
import ninja.blacknet.serialization.BinaryEncoder
import ninja.blacknet.serialization.Json

private val logger = KotlinLogging.logger {}

@Serializable
class CancelLease(
        val amount: Long,
        val to: PublicKey,
        val height: Int
) : TxData {
    override fun getType() = TxType.CancelLease
    override fun involves(publicKey: PublicKey) = to == publicKey
    override fun serialize() = BinaryEncoder.toBytes(serializer(), this)
    override fun toJson() = Json.toJson(Info.serializer(), Info(this))

    override suspend fun processImpl(tx: Transaction, hash: Hash, ledger: Ledger, undo: UndoBuilder): Boolean {
        val toAccount = ledger.get(to)
        if (toAccount == null) {
            logger.info("account not found")
            return false
        }
        undo.add(to, toAccount)
        if (toAccount.leases.remove(AccountState.LeaseInput(tx.from, height, amount))) {
            ledger.set(to, toAccount)
            val account = ledger.get(tx.from)!!
            account.debit(ledger.height(), amount)
            ledger.set(tx.from, account)
            return true
        }
        logger.info("lease not found")
        return false
    }

    @Suppress("unused")
    @Serializable
    class Info(
            val amount: String,
            val to: String,
            val height: Int
    ) {
        constructor(data: CancelLease) : this(
                data.amount.toString(),
                Address.encode(data.to),
                data.height
        )
    }
}
