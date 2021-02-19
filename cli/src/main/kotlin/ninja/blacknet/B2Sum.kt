/*
 * Copyright (c) 2019-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet

import com.rfksystems.blake2b.Blake2b
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import ninja.blacknet.codec.stringCodec
import java.io.File

object B2Sum {
    @JvmStatic
    fun main(args: Array<String>) {
        val hex = stringCodec("hex")
        val jobs = ArrayList<Job>(args.size)

        val DIGEST_SIZE_BITS = 256
        val DIGEST_SIZE_BYTES = DIGEST_SIZE_BITS / Byte.SIZE_BITS

        args.forEach { arg ->
            val job = GlobalScope.launch {
                val file = File(arg)
                val stream = try {
                    file.inputStream()
                } catch (e: Throwable) {
                    println("B2Sum: ${e.message}")
                    return@launch
                }
                val b2 = Blake2b(DIGEST_SIZE_BITS)
                val buffer = ByteArray(DEFAULT_BUFFER_SIZE)

                while (true) {
                    val n = stream.read(buffer)
                    if (n > 0) {
                        b2.update(buffer, 0, n)
                    } else {
                        break
                    }
                }

                stream.close()
                val bytes = ByteArray(DIGEST_SIZE_BYTES)
                b2.digest(bytes, 0)
                println("${hex.encode(bytes)} $arg")
            }

            jobs.add(job)
        }

        runBlocking {
            jobs.forEach { job ->
                job.join()
            }
        }
    }
}
