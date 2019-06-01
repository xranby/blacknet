/*
 * Copyright (c) 2019 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.network

import com.google.common.io.Resources
import io.ktor.util.error
import mu.KotlinLogging
import kotlin.math.min

private val logger = KotlinLogging.logger {}

object Bip14 {
    const val client = "Blacknet"
    val version = loadVersion()
    val agent = "/$client:$version/"

    fun sanitize(string: String): String {
        val length = min(string.length, MAX_LENGTH)
        val b = StringBuilder(length)
        for (i in 0 until length) {
            val c = string[i]
            if (SAFE_CHARS.contains(c))
                b.append(c)
        }
        return b.toString()
    }

    private const val MAX_LENGTH = 256
    private const val SAFE_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" + " .,;-_/:?@()"

    private fun loadVersion(): String {
        val string = try {
            Resources.toString(Resources.getResource("version.txt"), Charsets.US_ASCII)
        } catch (e: Throwable) {
            logger.error(e)
            ""
        }
        if (string.isEmpty()) {
            logger.warn("Running unknown version of $client")
            return "unknown"
        }
        return string
    }
}
