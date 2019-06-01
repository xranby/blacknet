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
import ninja.blacknet.serialization.SerializableByteArray
import ninja.blacknet.serialization.toHex

private val logger = KotlinLogging.logger {}

@Serializable
class CreateHTLC(
        val amount: Long,
        val to: PublicKey,
        val timeLockType: Byte,
        val timeLock: Long,
        val hashType: Byte,
        val hashLock: SerializableByteArray
) : TxData {
    override fun getType() = TxType.CreateHTLC
    override fun involves(publicKey: PublicKey) = to == publicKey
    override fun serialize() = BinaryEncoder.toBytes(serializer(), this)
    override fun toJson() = Json.toJson(Info.serializer(), Info(this))

    override suspend fun processImpl(tx: Transaction, hash: Hash, ledger: Ledger, undo: UndoBuilder): Boolean {
        if (!HTLC.isValidTimeLockType(timeLockType)) {
            logger.info("unknown timelock type $timeLockType")
            return false
        }
        if (!HTLC.isValidHashType(hashType)) {
            logger.info("unknown hash type $hashType")
            return false
        }

        if (amount == 0L) {
            logger.info("invalid amount")
            return false
        }

        val account = ledger.get(tx.from)!!
        if (!account.credit(amount))
            return false

        undo.addHTLC(hash, null)

        val htlc = HTLC(ledger.height(), ledger.blockTime(), amount, tx.from, to, timeLockType, timeLock, hashType, hashLock)
        ledger.set(tx.from, account)
        ledger.addHTLC(hash, htlc)
        return true
    }

    @Suppress("unused")
    @Serializable
    class Info(
            val amount: String,
            val to: String,
            val timeLockType: Int,
            val timeLock: Long,
            val hashType: Int,
            val hashLock: String
    ) {
        constructor(data: CreateHTLC) : this(
                data.amount.toString(),
                Address.encode(data.to),
                data.timeLockType.toUByte().toInt(),
                data.timeLock,
                data.hashType.toUByte().toInt(),
                data.hashLock.array.toHex()
        )
    }
}
