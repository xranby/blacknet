/*
 * Copyright (c) 2018 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.core

import ninja.blacknet.crypto.Hash
import ninja.blacknet.db.BlockDB

enum class DataType(
        val db: DataDB,
        val hash: (ByteArray) -> Hash
) {
    Block(BlockDB, ninja.blacknet.core.Block.Hasher),
    Transaction(TxPool, ninja.blacknet.core.Transaction.Hasher),
    ;

    companion object {
        const val MAX_INVENTORY = 50000
        const val MAX_DATA = 1000
    }
}