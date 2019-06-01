/*
 * Copyright (c) 2018 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.transaction

import kotlinx.serialization.json.JsonElement
import mu.KotlinLogging
import ninja.blacknet.core.DataDB
import ninja.blacknet.core.Ledger
import ninja.blacknet.core.Transaction
import ninja.blacknet.core.UndoBuilder
import ninja.blacknet.crypto.Hash
import ninja.blacknet.crypto.PublicKey
import ninja.blacknet.serialization.BinaryDecoder

private val logger = KotlinLogging.logger {}

interface TxData {
    fun getType(): TxType
    fun involves(publicKey: PublicKey): Boolean
    fun serialize(): ByteArray
    fun toJson(): JsonElement
    suspend fun processImpl(tx: Transaction, hash: Hash, ledger: Ledger, undo: UndoBuilder): Boolean

    suspend fun process(tx: Transaction, hash: Hash, ledger: Ledger, undo: UndoBuilder): DataDB.Status {
        val account = ledger.get(tx.from)
        if (account == null) {
            logger.info("account not found")
            return DataDB.Status.INVALID
        }
        if (tx.seq < account.seq) {
            logger.debug { "already have seq ${tx.seq}" }
            return DataDB.Status.ALREADY_HAVE
        } else if (tx.seq > account.seq) {
            logger.debug { "in future seq ${tx.seq}" }
            return DataDB.Status.IN_FUTURE
        }
        undo.add(tx.from, account)
        if (!account.credit(tx.fee)) {
            logger.info("insufficient funds for tx fee")
            return DataDB.Status.INVALID
        }
        account.prune(ledger.height())
        account.seq++
        ledger.set(tx.from, account)
        return if (processImpl(tx, hash, ledger, undo))
            DataDB.Status.ACCEPTED
        else
            DataDB.Status.INVALID
    }

    companion object {
        fun deserialize(type: Byte, bytes: ByteArray): TxData? {
            val serializer = TxType.getSerializer(type)
            if (serializer == null) {
                logger.info("unknown transaction type:$type")
                return null
            }
            return BinaryDecoder.fromBytes(bytes).decode(serializer)
        }
    }
}
