/*
 * Copyright (c) 2019-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.rpc.v2

import kotlinx.serialization.Serializable
import ninja.blacknet.db.WalletDB

@Serializable
class TransactionDataInfo(
        val types: List<WalletDB.TransactionDataType>,
        val time: Long,
        val height: Int
) {
    constructor(txData: WalletDB.TransactionData) : this(
            txData.types,
            txData.time,
            txData.height
    )
}
