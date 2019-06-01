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
import ninja.blacknet.crypto.Address
import ninja.blacknet.crypto.Mnemonic

@Serializable
class MnemonicInfo(
        val mnemonic: String,
        val address: String,
        val publicKey: String
) {
    companion object {
        fun new(): MnemonicInfo {
            val pair = Mnemonic.generate()
            val publicKey = pair.second.toPublicKey()
            return MnemonicInfo(pair.first, Address.encode(publicKey), publicKey.toString())
        }

        fun fromString(string: String?): MnemonicInfo? {
            if (string == null) return null
            val privateKey = Mnemonic.fromString(string) ?: return null
            val publicKey = privateKey.toPublicKey()
            return MnemonicInfo(string, Address.encode(publicKey), publicKey.toString())
        }
    }
}
