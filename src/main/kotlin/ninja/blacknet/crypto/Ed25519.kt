/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.crypto

import com.rfksystems.blake2b.Blake2b.BLAKE2_B_512
import net.i2p.crypto.eddsa.EdDSAEngine
import net.i2p.crypto.eddsa.EdDSAPrivateKey
import net.i2p.crypto.eddsa.EdDSAPublicKey
import net.i2p.crypto.eddsa.math.Curve
import net.i2p.crypto.eddsa.math.Field
import net.i2p.crypto.eddsa.math.FieldElement
import net.i2p.crypto.eddsa.math.GroupElement
import net.i2p.crypto.eddsa.math.ed25519.Ed25519FieldElement
import net.i2p.crypto.eddsa.math.ed25519.Ed25519LittleEndianEncoding
import net.i2p.crypto.eddsa.math.ed25519.Ed25519ScalarOps
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec
import ninja.blacknet.crypto.HashEncoder.Companion.buildHash
import ninja.blacknet.util.byteArrayOfInts
import java.security.MessageDigest
import kotlin.experimental.and
import kotlin.experimental.or
import kotlin.reflect.full.memberProperties
import kotlin.reflect.jvm.isAccessible

object Ed25519 {
    internal val field: Field
    private val curve: Curve
    private val B: GroupElement
    private val spec: EdDSANamedCurveSpec

    init {
        field = Field(256,
                byteArrayOfInts(0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f),
                Ed25519LittleEndianEncoding())
        curve = Curve(field,
                byteArrayOfInts(0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75, 0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00, 0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c, 0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52),
                field.fromByteArray(byteArrayOfInts(0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4, 0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f, 0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b, 0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b)))
        B = curve.createPoint(byteArrayOfInts(0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66),
                true)
        spec = EdDSANamedCurveSpec("Ed25519-Blake2b",
                curve,
                BLAKE2_B_512,
                Ed25519ScalarOps(),
                B)
    }

    fun toPublicKey(privateKey: ByteArray): ByteArray {
        val key = EdDSAPrivateKeySpec(privateKey, spec)
        return key.getA().toByteArray()
    }

    fun sign(hash: ByteArray, privateKey: ByteArray): ByteArray {
        val edDSAPrivateKeySpec = EdDSAPrivateKeySpec(privateKey, spec)
        val edDSAPrivateKey = EdDSAPrivateKey(edDSAPrivateKeySpec)
        val edDSAEngine = EdDSAEngine(MessageDigest.getInstance(BLAKE2_B_512))
        edDSAEngine.initSign(edDSAPrivateKey)
        edDSAEngine.setParameter(EdDSAEngine.ONE_SHOT_MODE)
        edDSAEngine.update(hash)
        return edDSAEngine.sign()
    }

    fun verify(signature: ByteArray, hash: ByteArray, publicKey: ByteArray): Boolean {
        val A = toGroupElement(publicKey)
        val edDSAPublicKeySpec = EdDSAPublicKeySpec(A, spec)
        val edDSAPublicKey = EdDSAPublicKey(edDSAPublicKeySpec)
        val edDSAEngine = EdDSAEngine(MessageDigest.getInstance(BLAKE2_B_512))
        edDSAEngine.initVerify(edDSAPublicKey)
        edDSAEngine.setParameter(EdDSAEngine.ONE_SHOT_MODE)
        edDSAEngine.update(hash)
        return edDSAEngine.verify(signature)
    }

    fun x25519(privateKey: ByteArray, publicKey: ByteArray): ByteArray {
        val pubKey = publicKeyToCurve25519(publicKey)
        val privKey = privateKeyToCurve25519(privateKey)

        var x1 = field.fromByteArray(pubKey)
        var x2 = field.ONE
        var z2 = field.ZERO
        var x3 = field.fromByteArray(pubKey)
        var z3 = field.ONE

        var swap = 0
        for (pos in 254 downTo 0) {
            val b = (privKey[pos / 8].toInt() shr (pos and 7)) and 1
            swap = swap xor b
            if (swap == 1) {
                x2 = x3.also { x3 = x2 }
                z2 = z3.also { z3 = z2 }
            }
            swap = b
            var tmp0 = x3 - z3
            var tmp1 = x2 - z2
            x2 = x2 + z2
            z2 = x3 + z3
            z3 = tmp0 * x2
            z2 = z2 * tmp1
            tmp0 = tmp1.square()
            tmp1 = x2.square()
            x3 = z3 + z2
            z2 = z3 - z2
            x2 = tmp1 * tmp0
            tmp1 = tmp1 - tmp0
            z2 = z2.square()
            z3 = tmp1.scalarProduct(121666)
            x3 = x3.square()
            tmp0 = tmp0 + z3
            z3 = x1 * z2
            z2 = tmp1 * tmp0
        }
        if (swap == 1) {
            x2 = x3.also { x3 = x2 }
            z2 = z3.also { z3 = z2 }
        }

        z2 = z2.invert()
        x2 = x2 * z2

        return x2.toByteArray()
    }

    private fun publicKeyToCurve25519(publicKey: ByteArray): ByteArray {
        val A = toGroupElement(publicKey)
        val one_minus_y = field.ONE - A.y
        val x = (field.ONE + A.y) * one_minus_y.invert()
        return x.toByteArray()
    }

    private fun privateKeyToCurve25519(privateKey: ByteArray): ByteArray {
        val hash = buildHash(BLAKE2_B_512) { encodeByteArray(privateKey) }
        val h = hash.copyOf(PrivateKeySerializer.SIZE_BYTES)
        h[0] = h[0] and 248.toByte()
        h[31] = h[31] and 127
        h[31] = h[31] or 64
        return h
    }

    private fun toGroupElement(publicKey: ByteArray): GroupElement {
        try {
            return GroupElement(curve, publicKey)
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("Invalid public key: not a valid point on the curve")
        }
    }
}

private fun FieldElement.getArray(): IntArray {
    val prop = (this as Ed25519FieldElement).javaClass.kotlin.memberProperties.find { it.name == "t" }!!
    prop.isAccessible = true
    return prop.get(this) as IntArray
}

private fun FieldElement.scalarProduct(n: Int): FieldElement {
    val f = getArray()
    val h = LongArray(f.size) { f[it] * n.toLong() }

    val carry9 = (h[9] + (1.toLong() shl 24)) shr 25
    h[0] += carry9 * 19
    h[9] -= carry9 * (1.toLong() shl 25)
    val carry1 = (h[1] + (1.toLong() shl 24)) shr 25
    h[2] += carry1
    h[1] -= carry1 * (1.toLong() shl 25)
    val carry3 = (h[3] + (1.toLong() shl 24)) shr 25
    h[4] += carry3
    h[3] -= carry3 * (1.toLong() shl 25)
    val carry5 = (h[5] + (1.toLong() shl 24)) shr 25
    h[6] += carry5
    h[5] -= carry5 * (1.toLong() shl 25)
    val carry7 = (h[7] + (1.toLong() shl 24)) shr 25
    h[8] += carry7
    h[7] -= carry7 * (1.toLong() shl 25)

    val carry0 = (h[0] + (1.toLong() shl 25)) shr 26
    h[1] += carry0
    h[0] -= carry0 * (1.toLong() shl 26)
    val carry2 = (h[2] + (1.toLong() shl 25)) shr 26
    h[3] += carry2
    h[2] -= carry2 * (1.toLong() shl 26)
    val carry4 = (h[4] + (1.toLong() shl 25)) shr 26
    h[5] += carry4
    h[4] -= carry4 * (1.toLong() shl 26)
    val carry6 = (h[6] + (1.toLong() shl 25)) shr 26
    h[7] += carry6
    h[6] -= carry6 * (1.toLong() shl 26)
    val carry8 = (h[8] + (1.toLong() shl 25)) shr 26
    h[9] += carry8
    h[8] -= carry8 * (1.toLong() shl 26)

    return Ed25519FieldElement(Ed25519.field, IntArray(h.size) { h[it].toInt() })
}

private operator fun FieldElement.times(element: FieldElement): FieldElement {
    return this.multiply(element)
}

private operator fun FieldElement.plus(element: FieldElement): FieldElement {
    return this.add(element)
}

private operator fun FieldElement.minus(element: FieldElement): FieldElement {
    return this.subtract(element)
}
