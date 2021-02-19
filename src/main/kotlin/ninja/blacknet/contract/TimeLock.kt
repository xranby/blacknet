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
import kotlinx.serialization.Serializable

const val TIME: Byte = 0
const val HEIGHT: Byte = 1
const val RELATIVE_TIME: Byte = 2
const val RELATIVE_HEIGHT: Byte = 3

@Serializable
class TimeLock(
        val type: Byte,
        val data: Long
) {
    fun validate(): Unit {
        when (type) {
            TIME -> Unit
            HEIGHT -> Unit
            RELATIVE_TIME -> Unit
            RELATIVE_HEIGHT -> Unit
            else -> throw RuntimeException("Unknown time type $type")
        }
    }

    fun verify(compilerHeight: Int, compilerTime: Long, height: Int, time: Long): Boolean {
        return when (type) {
            TIME -> data < time
            HEIGHT -> data < height
            RELATIVE_TIME -> compilerTime + data < time
            RELATIVE_HEIGHT -> compilerHeight + data < height
            else -> throw RuntimeException("Unknown time type $type")
        }
    }
}
