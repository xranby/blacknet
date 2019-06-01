/*
 * Copyright (c) 2018 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.api

import kotlinx.serialization.Serializable
import ninja.blacknet.core.TxPool

@Serializable
class TxPoolInfo(
        val size: Int,
        val dataSize: Int,
        val tx: List<String>
) {
    companion object {
        suspend fun get(): TxPoolInfo {
            val tx = TxPool.mapHashesToList { it.toString() }
            return TxPoolInfo(TxPool.size(), TxPool.dataSize(), tx)
        }
    }
}
