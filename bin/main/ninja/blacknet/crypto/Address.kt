/*
 * Copyright (c) 2018 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.crypto

object Address {
    private val HRP = "blacknet".toByteArray(Charsets.US_ASCII)

    fun encode(publicKey: PublicKey): String {
        return Bech32.encode(Bech32.Data(HRP, publicKey.bytes))
    }

    fun decode(string: String?): PublicKey? {
        if (string == null)
            return null
        val bech = Bech32.decode(string)
        if (bech == null || !HRP.contentEquals(bech.hrp))
            return null
        if (bech.data.size != PublicKey.SIZE)
            return null
        return PublicKey(bech.data)
    }
}