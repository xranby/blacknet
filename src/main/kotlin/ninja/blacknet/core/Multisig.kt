/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.core

import kotlinx.serialization.Serializable
import ninja.blacknet.crypto.PublicKeySerializer
import ninja.blacknet.serialization.LongSerializer
import ninja.blacknet.serialization.VarLongSerializer
import ninja.blacknet.util.sumByLong

@Serializable
class Multisig(
        val n: Byte,
        val deposits: List<DepositElement>
) {

    fun amount(): Long {
        return deposits.sumByLong { it.amount }
    }

    @Serializable
    class DepositElement(
            @Serializable(with = PublicKeySerializer::class)
            val from: ByteArray,
            @Serializable(with = LongSerializer::class)
            val amount: Long
    ) {
        operator fun component1() = from
        operator fun component2() = amount
    }
}
