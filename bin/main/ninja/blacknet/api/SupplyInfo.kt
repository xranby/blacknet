/*
 * Copyright (c) 2019 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.api

import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.Serializable
import ninja.blacknet.db.BlockDB
import ninja.blacknet.db.LedgerDB

@Serializable
class SupplyInfo(
        val height: Int,
        val blockHash: String,
        val blockTime: Long,
        val supply: String
) {
    companion object {
        suspend fun get(): SupplyInfo = BlockDB.mutex.withLock {
            return SupplyInfo(
                    LedgerDB.height(),
                    LedgerDB.blockHash().toString(),
                    LedgerDB.blockTime(),
                    LedgerDB.supply().toString()
            )
        }
    }
}
