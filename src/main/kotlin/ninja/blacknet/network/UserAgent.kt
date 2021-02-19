/*
 * Copyright (c) 2019-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.network

import ninja.blacknet.Version
import kotlin.math.min

/**
 * 用戶代理字符串
 *
 * Bitcoin improvement proposal 14 "Protocol Version and User Agent"
 */
object UserAgent {
    val string = "/${Version.name}:${Version.version}/"
    val prober = "/${Version.name}-prober:${Version.version}/"

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
}
