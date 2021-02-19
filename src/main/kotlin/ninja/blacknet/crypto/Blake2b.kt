/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.crypto

import com.rfksystems.blake2b.Blake2b.BLAKE2_B_256
import io.ktor.utils.io.pool.DefaultPool
import ninja.blacknet.Runtime

/**
 * BLAKE2b-256 hash function.
 */
object Blake2b {
    /**
     * Builds a hash value with the given [input] builder.
     *
     * @param input the initialization function with the [HashEncoder] receiver
     * @return the built hash value
     */
    inline fun buildHash(input: HashEncoder.() -> Unit): ByteArray {
        val coder = pool.borrow()
        return try {
            coder.input()
            coder.writer.finish()
        } catch (e: Throwable) {
            coder.writer.reset()
            throw e
        } finally {
            pool.recycle(coder)
        }
    }

    val pool = object : DefaultPool<HashEncoder>(Runtime.availableProcessors) {
        override fun produceInstance(): HashEncoder {
            return HashEncoder(HashWriterJvm(BLAKE2_B_256))
        }

        override fun clearInstance(instance: HashEncoder): HashEncoder {
            return instance
        }

        override fun validateInstance(instance: HashEncoder) {

        }

        override fun disposeInstance(instance: HashEncoder) {

        }
    }
}
