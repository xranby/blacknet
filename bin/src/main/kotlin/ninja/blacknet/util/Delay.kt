/*
 * Copyright (c) 2018 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.util

import kotlinx.coroutines.CoroutineScope

private const val SECONDS = 1000

suspend fun delay(seconds: Int) = kotlinx.coroutines.delay(seconds.toLong() * SECONDS)

suspend fun <T> withTimeout(seconds: Int, block: suspend CoroutineScope.() -> T): T =
        kotlinx.coroutines.withTimeout(seconds.toLong() * SECONDS, block)
