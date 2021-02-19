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
import ninja.blacknet.contract.HashLock
import ninja.blacknet.contract.TimeLock
import ninja.blacknet.crypto.PublicKeySerializer

@Serializable
class HTLC(
        val height: Int,
        val time: Long,
        val amount: Long,
        @Serializable(with = PublicKeySerializer::class)
        val from: ByteArray,
        @Serializable(with = PublicKeySerializer::class)
        val to: ByteArray,
        val timeLock: TimeLock,
        val hashLock: HashLock
) {

}
