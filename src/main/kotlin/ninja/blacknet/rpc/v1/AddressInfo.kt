/*
 * Copyright (c) 2019-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.rpc.v1

import kotlinx.serialization.Serializable
import ninja.blacknet.codec.base.Base16
import ninja.blacknet.crypto.Address

@Serializable
class AddressInfo(
        val publicKey: String
) {
    companion object {
        fun fromString(string: String): AddressInfo {
            val publicKey = Address.decode(string)
            return AddressInfo(Base16.encode(publicKey))
        }
    }
}
