/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.rpc.v1

import java.math.BigInteger
import kotlinx.serialization.Serializable
import ninja.blacknet.crypto.BigIntegerSerializer
import ninja.blacknet.crypto.HashSerializer
import ninja.blacknet.db.LedgerDB
import ninja.blacknet.serialization.LongSerializer

@Serializable
class LedgerInfo(
        val height: Int,
        @Serializable(with = HashSerializer::class)
        val blockHash: ByteArray,
        val blockTime: Long,
        @Serializable(with = HashSerializer::class)
        val rollingCheckpoint: ByteArray,
        @Serializable(with = BigIntegerSerializer::class)
        val difficulty: BigInteger,
        @Serializable(with = BigIntegerSerializer::class)
        val cumulativeDifficulty: BigInteger,
        @Serializable(with = LongSerializer::class)
        val supply: Long,
        val maxBlockSize: Int,
        @Serializable(with = HashSerializer::class)
        val nxtrng: ByteArray
) {
    companion object {
        fun get(): LedgerInfo {
            val state = LedgerDB.state()
            return LedgerInfo(
                    state.height,
                    state.blockHash,
                    state.blockTime,
                    state.rollingCheckpoint,
                    state.difficulty,
                    state.cumulativeDifficulty,
                    state.supply,
                    state.maxBlockSize,
                    state.nxtrng
            )
        }
    }
}
