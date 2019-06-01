/*
 * Copyright (c) 2018 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.crypto

import org.bouncycastle.crypto.digests.RIPEMD160Digest

object RIPEMD160 : (ByteArray) -> ByteArray {
    const val DIGEST_SIZE = 160

    fun hash(message: ByteArray): ByteArray {
        val bytes = ByteArray(DIGEST_SIZE / 8)
        val digest = RIPEMD160Digest()
        digest.update(message, 0, message.size)
        digest.doFinal(bytes, 0)
        return bytes
    }

    override fun invoke(bytes: ByteArray): ByteArray = hash(bytes)
}
