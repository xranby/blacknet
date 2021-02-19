/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet

import kotlinx.coroutines.*
import kotlinx.coroutines.sync.withLock
import mu.KotlinLogging
import ninja.blacknet.logging.error
import ninja.blacknet.util.SynchronizedArrayList
import kotlin.coroutines.CoroutineContext

private val logger = KotlinLogging.logger {}

object Runtime : CoroutineScope {
    override val coroutineContext: CoroutineContext = Dispatchers.Default
    private val shutdownHooks = SynchronizedArrayList<suspend () -> Unit>()

    /**
     * The number of available CPU, including virtual cores.
     */
    val availableProcessors = java.lang.Runtime.getRuntime().availableProcessors()

    /**
     * Running on macOS.
     */
    val macOS: Boolean

    /**
     * Running on Windows.
     */
    val windowsOS: Boolean

    /**
     * Registers a new shutdown hook.
     *
     * All registered shutdown hooks will be run sequentially in the reversed order.
     */
    fun addShutdownHook(hook: suspend () -> Unit) {
        runBlocking {
            shutdownHooks.mutex.withLock {
                shutdownHooks.list.add(hook)
                if (shutdownHooks.list.size == 1) {
                    java.lang.Runtime.getRuntime().addShutdownHook(ShutdownHooks())
                }
            }
        }
    }

    init {
        System.getProperty("os.name").let { os_name ->
            macOS = os_name.startsWith("Mac")
            windowsOS = os_name.startsWith("Windows")
        }
    }

    private class ShutdownHooks() : Thread() {
        override fun run() {
            logger.info("Shutdown is in progress...")
            runBlocking {
                shutdownHooks.reversedForEach { hook ->
                    try {
                        hook()
                    } catch (e: Throwable) {
                        logger.error(e)
                    }
                }
            }
        }
    }

    /**
     * Rotate [wheel].
     */
    inline fun rotate(crossinline wheel: suspend () -> Unit): Job {
        return launch {
            while (true) {
                wheel()
            }
        }
    }
}
