/*
 * Copyright (c) 2019 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.api

import kotlinx.serialization.Serializable
import ninja.blacknet.core.Block
import ninja.blacknet.crypto.Address
import ninja.blacknet.crypto.Hash

@Serializable
class BlockNotification(
        val hash: String,
        val height: Int,
        val size: Int,
        val version: Int,
        val previous: String,
        val time: Long,
        val generator: String,
        val txns: Int
) {
    constructor(block: Block, hash: Hash, height: Int, size: Int) : this(
            hash.toString(),
            height,
            size,
            block.version,
            block.previous.toString(),
            block.time,
            Address.encode(block.generator),
            block.transactions.size
    )
}
