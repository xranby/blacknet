/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.crypto

import org.bouncycastle.crypto.engines.ChaCha7539Engine
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import java.security.SecureRandom

/**
 * ChaCha20 stream cipher.
 */
object ChaCha20 {
    private const val IV_SIZE = 12
    private val random = SecureRandom()

    /**
     * Returns a [ByteArray] encrypted with [key].
     */
    fun encrypt(key: ByteArray, bytes: ByteArray): ByteArray {
        val encrypted = ByteArray(bytes.size + IV_SIZE)
        val iv = random.nextBytes(IV_SIZE)
        System.arraycopy(iv, 0, encrypted, 0, IV_SIZE)
        val engine = ChaCha7539Engine()
        engine.init(true, ParametersWithIV(KeyParameter(key), iv))
        engine.processBytes(bytes, 0, bytes.size, encrypted, IV_SIZE)
        return encrypted
    }

    /**
     * Returns a [ByteArray] decrypted with [key] or `null`.
     */
    fun decrypt(key: ByteArray, bytes: ByteArray): ByteArray? {
        val size = bytes.size - IV_SIZE
        if (size < 0) return null
        val iv = bytes.copyOf(IV_SIZE)
        val decrypted = ByteArray(size)
        val engine = ChaCha7539Engine()
        engine.init(false, ParametersWithIV(KeyParameter(key), iv))
        return if (engine.processBytes(bytes, IV_SIZE, size, decrypted, 0) == size)
            decrypted
        else
            null
    }

    /**
     * Returns an encrypted [string] with [key] using the UTF-8 charset.
     */
    fun encryptUtf8(key: ByteArray, string: String): ByteArray {
        return encrypt(key, string.toByteArray(Charsets.UTF_8))
    }

    /**
     * Returns a decrypted [String] with [key] using the UTF-8 charset or `null`.
     */
    fun decryptUtf8(key: ByteArray, bytes: ByteArray): String? {
        return decrypt(key, bytes)?.let { decrypted ->
            try {
                String(decrypted, Charsets.UTF_8)
            } catch (e: Throwable) {
                null
            }
        }
    }
}

internal fun SecureRandom.nextBytes(n: Int): ByteArray {
    val bytes = ByteArray(n)
    nextBytes(bytes)
    return bytes
}
