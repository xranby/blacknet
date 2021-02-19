/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.crypto

import ninja.blacknet.util.Resources

/**
 * Wordlists for mnemonic.
 *
 * Bitcoin improvement proposal 39 "Mnemonic code for generating deterministic keys"
 */
object Wordlists {
    fun get(name: String): Array<String> {
        return when (name) {
            "english" -> ENGLISH
            "chinese_simplified" -> CHINESE_SIMPLIFIED
            "chinese_traditional" -> CHINESE_TRADITIONAL
            "italian" -> ITALIAN
            "korean" -> KOREAN
            else -> throw RuntimeException("Unknown wordlist $name")
        }
    }

    private val ENGLISH by lazy { load("english") }
    private val CHINESE_SIMPLIFIED by lazy { load("chinese_simplified") }
    private val CHINESE_TRADITIONAL by lazy { load("chinese_traditional") }
    private val ITALIAN by lazy { load("italian") }
    private val KOREAN by lazy { load("korean") }

    private fun load(name: String): Array<String> {
        return Resources.lines(Wordlists::class.java, "bip39/$name.txt", Charsets.UTF_8).toTypedArray()
    }
}
