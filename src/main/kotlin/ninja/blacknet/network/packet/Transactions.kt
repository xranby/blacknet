/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.network.packet

import kotlinx.serialization.Serializable
import mu.KotlinLogging
import ninja.blacknet.core.*
import ninja.blacknet.crypto.HashSerializer
import ninja.blacknet.network.Connection
import ninja.blacknet.network.TxFetcher
import ninja.blacknet.network.Node
import ninja.blacknet.serialization.ByteArraySerializer

private val logger = KotlinLogging.logger {}

@Serializable
class Transactions(
        private val list: ArrayList<@Serializable(ByteArraySerializer::class) ByteArray>
) : Packet {
    override suspend fun process(connection: Connection) {
        if (list.size > MAX) {
            connection.dos("Invalid Transactions size ${list.size}")
            return
        }

        val inv = UnfilteredInvList()
        val time = connection.lastPacketTime

        for (bytes in list) {
            val hash = Transaction.hash(bytes)

            if (!TxFetcher.fetched(hash)) {
                connection.dos("Unrequested ${HashSerializer.encode(hash)}")
                continue
            }

            val (status, fee) = TxPool.process(hash, bytes, time / 1000L, true)

            when (status) {
                Accepted -> inv.add(Pair(hash, fee))
                is Invalid -> connection.dos("$status ${HashSerializer.encode(hash)}")
                is InFuture -> logger.debug { "$status ${HashSerializer.encode(hash)}" }
                is NotOnThisChain -> logger.debug { "$status ${HashSerializer.encode(hash)}" }
                is AlreadyHave -> logger.debug { "$status ${HashSerializer.encode(hash)}" }
            }
        }

        if (inv.isNotEmpty()) {
            Node.broadcastInv(inv, connection)
            connection.lastTxTime = time
        }
    }

    companion object {
        const val MAX = 1000
    }
}
