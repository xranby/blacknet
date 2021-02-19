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
import ninja.blacknet.core.TxPool
import ninja.blacknet.crypto.HashSerializer

@Serializable
class TxPoolInfo(
        val size: Int,
        val dataSize: Int,
        val tx: List<String>
) {
    companion object {
        suspend fun get(): TxPoolInfo = TxPool.mutex.withLock {
            val tx = TxPool.mapHashesToListImpl { HashSerializer.encode(it) }
            return TxPoolInfo(TxPool.sizeImpl(), TxPool.dataSizeImpl(), tx)
        }
    }
}
