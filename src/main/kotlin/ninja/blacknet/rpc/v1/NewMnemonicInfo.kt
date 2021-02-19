/*
 * Copyright (c) 2018-2020 Pavel Vasin
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
import ninja.blacknet.crypto.Ed25519
import ninja.blacknet.crypto.Mnemonic

@Serializable
class NewMnemonicInfo(
        val mnemonic: String,
        val address: String,
        val publicKey: String
) {
    companion object {
        fun new(wordlist: Array<String>): NewMnemonicInfo {
            val (mnemonic, privateKey) = Mnemonic.generate(wordlist)
            val publicKey = Ed25519.toPublicKey(privateKey)
            return NewMnemonicInfo(mnemonic, Address.encode(publicKey), Base16.encode(publicKey))
        }

        fun fromString(string: String): NewMnemonicInfo {
            val privateKey = Mnemonic.fromString(string)
            val publicKey = Ed25519.toPublicKey(privateKey)
            return NewMnemonicInfo(string, Address.encode(publicKey), Base16.encode(publicKey))
        }
    }
}
