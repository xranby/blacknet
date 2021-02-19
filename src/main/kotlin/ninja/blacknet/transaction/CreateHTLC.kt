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
import ninja.blacknet.contract.HashLock
import ninja.blacknet.contract.TimeLock
import ninja.blacknet.core.*
import ninja.blacknet.crypto.Address
import ninja.blacknet.crypto.Blake2b.buildHash
import ninja.blacknet.crypto.PublicKeySerializer
import ninja.blacknet.crypto.encodeByteArray
import ninja.blacknet.serialization.LongSerializer

/**
 * 創建合約
 */
@Serializable
class CreateHTLC(
        @Serializable(with = LongSerializer::class)
        val amount: Long,
        @Serializable(with = PublicKeySerializer::class)
        val to: ByteArray,
        val timeLock: TimeLock,
        val hashLock: HashLock
) : TxData {
    fun id(hash: ByteArray, dataIndex: Int): ByteArray =
        buildHash {
            encodeByteArray(hash);
            encodeInt(dataIndex);
        }

    override fun processImpl(tx: Transaction, hash: ByteArray, dataIndex: Int, ledger: Ledger): Status {
        try {
            timeLock.validate()
        } catch (e: Throwable) {
            return Invalid("Invalid time lock ${e.message}")
        }
        try {
            hashLock.validate()
        } catch (e: Throwable) {
            return Invalid("Invalid hash lock ${e.message}")
        }

        if (amount == 0L) {
            return Invalid("Invalid amount")
        }

        val account = ledger.getAccount(tx.from)!!
        val status = account.credit(amount)
        if (status != Accepted) {
            return status
        }

        val id = id(hash, dataIndex)
        val htlc = HTLC(ledger.height(), ledger.blockTime(), amount, tx.from, to, timeLock, hashLock)
        ledger.setAccount(tx.from, account)
        ledger.addHTLC(id, htlc)
        return Accepted
    }

    fun involves(publicKey: ByteArray) = to.contentEquals(publicKey)
}
