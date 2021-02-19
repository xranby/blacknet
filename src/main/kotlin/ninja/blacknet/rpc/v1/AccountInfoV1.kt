/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.rpc.v1

import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.Serializable
import ninja.blacknet.db.BlockDB
import ninja.blacknet.db.LedgerDB

@Serializable
class AccountInfoV1(
        val seq: Int,
        val balance: Long,
        val confirmedBalance: Long,
        val stakingBalance: Long
) {
    companion object {
        suspend fun get(publicKey: ByteArray, confirmations: Int): AccountInfoV1? = BlockDB.mutex.withLock {
            val account = LedgerDB.get(publicKey) ?: return null
            val state = LedgerDB.state()
            return AccountInfoV1(
                    account.seq,
                    account.balance(),
                    account.confirmedBalance(state.height, confirmations),
                    account.stakingBalance(state.height))
        }
    }
}
