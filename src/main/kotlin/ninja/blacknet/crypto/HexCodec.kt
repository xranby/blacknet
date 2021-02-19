/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

@file:Suppress("UNUSED_ANONYMOUS_PARAMETER")

package ninja.blacknet.crypto

import ninja.blacknet.codec.base.Base16
import ninja.blacknet.codec.base.HexCodecException

/**
 * Returns the byte array representation of a hex-string.
 * @param string the hex-string
 * @param length the expected length of the byte array
 * @return the decoded [ByteArray]
 * @throws HexCodecException if the string is not a hexadecimal number or its length does not match the expected value
 */
@Throws(HexCodecException::class)
fun decodeHex(string: String, length: Int): ByteArray {
    return Base16.decode(string).also { bytes ->
        if (string.length != length)
            throw HexCodecException("Expected length $length actual ${string.length}")
    }
}

/**
 * Returns the hex-string representation of a byte array.
 * @param bytes the byte array
 * @param length the expected length of the byte array
 * @return the decoded [String]
 * @throws HexCodecException if length of the string does not match the expected value
 */
@Throws(HexCodecException::class)
fun encodeHex(bytes: ByteArray, length: Int): String {
    return Base16.encode(bytes).also { string ->
        if (string.length != length)
            throw HexCodecException("Expected length $length actual ${string.length}")
    }
}
