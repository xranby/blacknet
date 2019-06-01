/*
 * Copyright (c) 2018-2019 Pavel Vasin
 * Copyright (c) 2019 Blacknet Team
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
import ninja.blacknet.crypto.Hash
import ninja.blacknet.crypto.PublicKey
import ninja.blacknet.db.LedgerDB
import ninja.blacknet.serialization.BinaryEncoder
import ninja.blacknet.serialization.Json

private val logger = KotlinLogging.logger {}

@Serializable
class RefundHTLC(
        val id: Hash
) : TxData {
    override fun getType() = TxType.RefundHTLC
    override fun involves(publicKey: PublicKey) = LedgerDB.getHTLC(id)!!.involves(publicKey)
    override fun serialize() = BinaryEncoder.toBytes(serializer(), this)
    override fun toJson() = Json.toJson(serializer(), this)

    override suspend fun processImpl(tx: Transaction, hash: Hash, ledger: Ledger, undo: UndoBuilder): Boolean {
        val htlc = ledger.getHTLC(id)
        if (htlc == null) {
            logger.info("htlc not found")
            return false
        }
        if (tx.from != htlc.from) {
            logger.info("invalid sender")
            return false
        }
        if (!htlc.verifyTimeLock(ledger)) {
            logger.info("invalid timelock")
            return false
        }

        undo.addHTLC(id, htlc)

        val account = ledger.get(tx.from)!!
        account.debit(ledger.height(), htlc.amount)
        ledger.set(tx.from, account)
        ledger.removeHTLC(id)
        return true
    }
}
