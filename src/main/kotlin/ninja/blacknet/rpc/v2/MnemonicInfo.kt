/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.rpc.v2

import kotlinx.serialization.Serializable
import ninja.blacknet.codec.base.Base16
import ninja.blacknet.crypto.Address
import ninja.blacknet.crypto.Ed25519
import ninja.blacknet.crypto.Mnemonic

@Serializable
class MnemonicInfo(
        val address: String,
        val publicKey: String
) {
    companion object {
        fun fromString(string: String): MnemonicInfo {
            val privateKey = Mnemonic.fromString(string)
            val publicKey = Ed25519.toPublicKey(privateKey)
            return MnemonicInfo(Address.encode(publicKey), Base16.encode(publicKey))
        }
    }
}
