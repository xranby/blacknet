/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.serialization

import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonEncoder
import ninja.blacknet.crypto.HashEncoder
import ninja.blacknet.rpc.requests.RequestDecoder
import ninja.blacknet.serialization.bbf.*

/**
 * Serializes an [Int] with variable number of bytes in a binary representation.
 */
object VarIntSerializer : KSerializer<Int> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor(
        "ninja.blacknet.serialization.VarIntSerializer",
        PrimitiveKind.INT
    )

    override fun deserialize(decoder: Decoder): Int {
        return when (decoder) {
            is BinaryDecoder -> decoder.decodeVarInt()
            is JsonDecoder, is RequestDecoder -> decoder.decodeInt()
            else -> throw notSupportedFormatError(decoder, this)
        }
    }

    override fun serialize(encoder: Encoder, value: Int) {
        when (encoder) {
            is BinaryEncoder -> encoder.encodeVarInt(value)
            is HashEncoder, is JsonEncoder -> encoder.encodeInt(value)
            else -> throw notSupportedFormatError(encoder, this)
        }
    }
}
