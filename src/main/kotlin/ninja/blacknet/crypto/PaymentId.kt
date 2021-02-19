/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.crypto

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Serializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonEncoder
import ninja.blacknet.codec.base.Base16
import ninja.blacknet.crypto.Blake2b.buildHash
import ninja.blacknet.crypto.Ed25519.x25519
import ninja.blacknet.serialization.bbf.BinaryDecoder
import ninja.blacknet.serialization.bbf.BinaryEncoder
import ninja.blacknet.serialization.notSupportedFormatError
import ninja.blacknet.util.emptyByteArray

@Serializable
class PaymentId(
        val type: Byte,
        @SerialName("message")
        val payload: ByteArray
) {
    fun isEmpty(): Boolean {
        return type == PLAIN && payload.isEmpty()
    }

    fun decrypt(privateKey: ByteArray, publicKey: ByteArray): String? {
        val sharedKey = sharedKey(privateKey, publicKey)
        return ChaCha20.decryptUtf8(sharedKey, payload)
    }

    @Serializer(forClass = PaymentId::class)
    companion object {
        const val PLAIN: Byte = 0
        const val ENCRYPTED: Byte = 1
        val EMPTY = PaymentId(PLAIN, emptyByteArray())

        fun create(string: String?, type: Byte?, privateKey: ByteArray?, publicKey: ByteArray?): PaymentId? {
            if (string == null)
                return EMPTY

            if (type == null || type == PLAIN)
                return plain(string)

            if (type != ENCRYPTED || privateKey == null || publicKey == null)
                return null

            return encrypted(string, privateKey, publicKey)
        }

        fun plain(string: String): PaymentId {
            return PaymentId(PLAIN, string.toByteArray(Charsets.UTF_8))
        }

        fun encrypted(string: String, privateKey: ByteArray, publicKey: ByteArray): PaymentId {
            val sharedKey = sharedKey(privateKey, publicKey)
            return PaymentId(ENCRYPTED, ChaCha20.encryptUtf8(sharedKey, string))
        }

        fun decrypt(privateKey: ByteArray, publicKey: ByteArray, hex: String): String? {
            val sharedKey = sharedKey(privateKey, publicKey)
            val bytes = try {
                Base16.decode(hex)
            } catch (e: Throwable) {
                return null
            }
            return ChaCha20.decryptUtf8(sharedKey, bytes)
        }

        private fun sharedKey(privateKey: ByteArray, publicKey: ByteArray): ByteArray {
            val sharedSecret = x25519(privateKey, publicKey)
            return buildHash {
                encodeByteArray(sharedSecret)
            }
        }

        override fun deserialize(decoder: Decoder): PaymentId {
            return when (decoder) {
                is BinaryDecoder -> PaymentId(decoder.decodeByte(), decoder.decodeByteArray())
                else -> throw notSupportedFormatError(decoder, this)
            }
        }

        override fun serialize(encoder: Encoder, value: PaymentId) {
            when (encoder) {
                is BinaryEncoder -> {
                    encoder.encodeByte(value.type)
                    encoder.encodeByteArray(value.payload)
                }
                is JsonEncoder -> {
                    @Suppress("NAME_SHADOWING")
                    val encoder = encoder.beginStructure(descriptor)
                    encoder.encodeSerializableElement(descriptor, 0, Byte.serializer(), value.type)
                    encoder.encodeSerializableElement(descriptor, 1, String.serializer(), if (value.type == PLAIN) String(value.payload) else Base16.encode(value.payload))
                    encoder.endStructure(descriptor)
                }
                else -> throw notSupportedFormatError(encoder, this)
            }
        }
    }
}
