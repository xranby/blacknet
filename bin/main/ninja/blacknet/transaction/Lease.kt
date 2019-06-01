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
import ninja.blacknet.serialization.BinaryDecoder
import ninja.blacknet.serialization.BinaryEncoder
import ninja.blacknet.serialization.Json

private val logger = KotlinLogging.logger {}

@Serializable
class Lease(
        val amount: Long,
        val to: PublicKey
) : TxData {
    override fun getType() = TxType.Lease
    override fun involves(publicKey: PublicKey) = to == publicKey
    override fun serialize() = BinaryEncoder.toBytes(serializer(), this)
    override fun toJson() = Json.toJson(Info.serializer(), Info(this))

    override suspend fun processImpl(tx: Transaction, hash: Hash, ledger: Ledger, undo: UndoBuilder): Boolean {
        if (amount < PoS.MIN_LEASE) {
            logger.info("$amount less than minimal ${PoS.MIN_LEASE}")
            return false
        }
        val account = ledger.get(tx.from)!!
        if (!account.credit(amount))
            return false
        ledger.set(tx.from, account)
        val toAccount = ledger.getOrCreate(to)
        undo.add(to, toAccount)
        toAccount.leases.add(AccountState.Lease(tx.from, ledger.height(), amount))
        ledger.set(to, toAccount)
        return true
    }

    companion object {
        fun deserialize(bytes: ByteArray): Lease? = BinaryDecoder.fromBytes(bytes).decode(serializer())
    }

    @Suppress("unused")
    @Serializable
    class Info(
            val amount: String,
            val to: String
    ) {
        constructor(data: Lease) : this(
                data.amount.toString(),
                Address.encode(data.to)
        )
    }
}
