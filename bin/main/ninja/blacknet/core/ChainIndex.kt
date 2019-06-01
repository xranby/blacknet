/*
 * Copyright (c) 2019 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.core

import kotlinx.serialization.*
import kotlinx.serialization.json.JsonOutput
import ninja.blacknet.crypto.Hash
import ninja.blacknet.serialization.BinaryDecoder
import ninja.blacknet.serialization.BinaryEncoder

@Serializable
class ChainIndex(
        val previous: Hash,
        var next: Hash,
        var nextSize: Int,
        val height: Int,
        val generated: Long
) {
    fun serialize(): ByteArray = BinaryEncoder.toBytes(serializer(), this)

    @Serializer(forClass = ChainIndex::class)
    companion object {
        fun deserialize(bytes: ByteArray): ChainIndex? = BinaryDecoder.fromBytes(bytes).decode(serializer())

        override fun deserialize(decoder: Decoder): ChainIndex {
            return when (decoder) {
                is BinaryDecoder -> ChainIndex(
                        Hash(decoder.decodeByteArrayValue(Hash.SIZE)),
                        Hash(decoder.decodeByteArrayValue(Hash.SIZE)),
                        decoder.unpackInt(),
                        decoder.unpackInt(),
                        decoder.unpackLong())
                else -> throw RuntimeException("unsupported decoder")
            }
        }

        override fun serialize(encoder: Encoder, obj: ChainIndex) {
            when (encoder) {
                is BinaryEncoder -> {
                    encoder.encodeByteArrayValue(obj.previous.bytes)
                    encoder.encodeByteArrayValue(obj.next.bytes)
                    encoder.packInt(obj.nextSize)
                    encoder.packInt(obj.height)
                    encoder.packLong(obj.generated)
                }
                is JsonOutput -> {
                    @Suppress("NAME_SHADOWING")
                    val encoder = encoder.beginStructure(descriptor)
                    encoder.encodeSerializableElement(descriptor, 0, Hash.serializer(), obj.previous)
                    encoder.encodeSerializableElement(descriptor, 1, Hash.serializer(), obj.next)
                    encoder.encodeSerializableElement(descriptor, 2, Int.serializer(), obj.nextSize)
                    encoder.encodeSerializableElement(descriptor, 3, Int.serializer(), obj.height)
                    encoder.encodeSerializableElement(descriptor, 4, Long.serializer(), obj.generated)
                    encoder.endStructure(descriptor)
                }
                else -> throw RuntimeException("unsupported encoder")
            }
        }
    }
}
