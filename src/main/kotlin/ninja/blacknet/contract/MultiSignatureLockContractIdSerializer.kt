/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.contract

import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import ninja.blacknet.crypto.Address
import ninja.blacknet.crypto.HashEncoder
import ninja.blacknet.crypto.HashSerializer
import ninja.blacknet.crypto.encodeByteArray
import ninja.blacknet.serialization.ContextualSerializer
import ninja.blacknet.serialization.bbf.BinaryDecoder
import ninja.blacknet.serialization.bbf.BinaryEncoder
import ninja.blacknet.serialization.notSupportedFormatError
import ninja.blacknet.serialization.descriptor.ListSerialDescriptor

/**
 * Contextual serializer for an id of the multisignature lock contract.
 */
object MultiSignatureLockContractIdSerializer : ContextualSerializer<ByteArray>() {
    /**
     * The number of bytes in a binary representation of the multisignature lock contract id.
     */
    const val SIZE_BYTES = HashSerializer.SIZE_BYTES

    fun decode(string: String): ByteArray {
        return Address.decode(Address.MULTISIG, string)
    }

    fun encode(id: ByteArray): String {
        return Address.encode(Address.MULTISIG, id)
    }
}

/**
 * Serializes an id of the multisignature lock contract.
 */
object MultiSignatureLockContractIdAsBinarySerializer : KSerializer<ByteArray> {
    override val descriptor: SerialDescriptor = ListSerialDescriptor(
            "ninja.blacknet.contract.MultiSignatureLockContractIdAsBinarySerializer",
            Byte.serializer().descriptor
    )

    override fun deserialize(decoder: Decoder): ByteArray {
        return when (decoder) {
            is BinaryDecoder -> decoder.decodeFixedByteArray(MultiSignatureLockContractIdSerializer.SIZE_BYTES)
            else -> throw notSupportedFormatError(decoder, this)
        }
    }

    override fun serialize(encoder: Encoder, value: ByteArray) {
        when (encoder) {
            is BinaryEncoder -> encoder.encodeFixedByteArray(value)
            is HashEncoder -> encoder.encodeByteArray(value)
            else -> throw notSupportedFormatError(encoder, this)
        }
    }
}

/**
 * Serializes an id of the multisignature lock contract.
 */
object MultiSignatureLockContractIdAsStringSerializer : KSerializer<ByteArray> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor(
            "ninja.blacknet.contract.MultiSignatureLockContractIdAsStringSerializer",
            PrimitiveKind.STRING
    )

    override fun deserialize(decoder: Decoder): ByteArray {
        return MultiSignatureLockContractIdSerializer.decode(decoder.decodeString())
    }

    override fun serialize(encoder: Encoder, value: ByteArray) {
        encoder.encodeString(MultiSignatureLockContractIdSerializer.encode(value))
    }
}
