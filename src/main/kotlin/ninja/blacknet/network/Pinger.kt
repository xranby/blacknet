/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.network

import com.google.common.primitives.Ints
import mu.KotlinLogging
import ninja.blacknet.Runtime
import ninja.blacknet.crypto.Blake2b
import ninja.blacknet.packet.Ping
import ninja.blacknet.packet.Pong
import ninja.blacknet.util.delay
import kotlin.random.Random

private val logger = KotlinLogging.logger {}

/**
 * 游戏护卫
 */
object Pinger {
    suspend fun implementation(connection: Connection) {
        delay(Node.NETWORK_TIMEOUT)

        if (connection.state.isConnected()) {
            delay(Random.nextInt(Node.NETWORK_TIMEOUT))
            sendPing(connection)
        } else {
            connection.close()
            return
        }

        while (true) {
            delay(Node.NETWORK_TIMEOUT)

            if (connection.pingRequest == null) {
                if (Runtime.time() > connection.lastPacketTime + Node.NETWORK_TIMEOUT) {
                    sendPing(connection)
                }
            } else {
                logger.info("Disconnecting ${connection.debugName()} on ping timeout")
                connection.close()
                return
            }
        }
    }

    fun ping(connection: Connection, ping: Ping) {
        val solution = if (connection.version >= MIN_VERSION)
            solve(ping.challenge)
        else
            ping.challenge

        connection.sendPacket(Pong(solution))
    }

    fun pong(connection: Connection, pong: Pong) {
        val (challenge, requestTime) = connection.pingRequest ?: return connection.dos("Unexpected Pong")

        val solution = if (connection.version >= MIN_VERSION)
            solve(challenge)
        else
            challenge

        if (pong.response != solution) {
            connection.dos("Invalid Pong")
            return
        }

        connection.ping = Runtime.timeMilli() - requestTime
        connection.pingRequest = null
    }

    private fun sendPing(connection: Connection) {
        val challenge = Random.nextInt()
        connection.pingRequest = Pair(challenge, Runtime.timeMilli())
        connection.sendPacket(Ping(challenge))
    }

    private fun solve(challenge: Int): Int {
        val hash = Blake2b.hasher { this + Node.magic + challenge }
        return Ints.fromBytes(hash.bytes[0], hash.bytes[1], hash.bytes[2], hash.bytes[3])
    }

    const val MIN_VERSION = 13
}
