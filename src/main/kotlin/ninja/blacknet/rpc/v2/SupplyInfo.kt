/*
 * Copyright (c) 2019-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.rpc.v2

import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.Serializable
import ninja.blacknet.crypto.HashSerializer
import ninja.blacknet.db.BlockDB
import ninja.blacknet.db.LedgerDB
import ninja.blacknet.serialization.LongSerializer

@Serializable
class SupplyInfo(
        val height: Int,
        @Serializable(with = HashSerializer::class)
        val blockHash: ByteArray,
        val blockTime: Long,
        @Serializable(with = LongSerializer::class)
        val supply: Long
) {
    companion object {
        suspend fun get(): SupplyInfo = BlockDB.mutex.withLock {
            val state = LedgerDB.state()
            return SupplyInfo(
                    state.height,
                    state.blockHash,
                    state.blockTime,
                    state.supply
            )
        }
    }
}
