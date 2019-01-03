/*
 * Copyright (c) 2018 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.network

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ClosedReceiveChannelException
import kotlinx.coroutines.io.*
import kotlinx.coroutines.launch
import kotlinx.io.IOException
import kotlinx.io.core.ByteReadPacket
import mu.KotlinLogging
import ninja.blacknet.serialization.BlacknetDecoder
import kotlin.coroutines.CoroutineContext

private val logger = KotlinLogging.logger {}

class Connection(
        private val readChannel: ByteReadChannel,
        private val writeChannel: ByteWriteChannel,
        val remoteAddress: Address,
        val localAddress: Address,
        var state: State
) : CoroutineScope {
    override val coroutineContext: CoroutineContext = Dispatchers.Default
    private val sendChannel: Channel<ByteReadPacket> = Channel(Channel.UNLIMITED)
    val connectedAt = Node.time()

    var version: Int = 0
    var agent: String = ""
    var feeFilter: Long = 0
    var timeOffset: Long = 0
    var pingRequest: PingRequest? = null
    var ping: Long = 0
    var dosScore: Int = 0

    init {
        launch { receiver() }
        launch { sender() }
    }

    fun totalBytesRead() = readChannel.totalBytesRead
    fun totalBytesWritten() = writeChannel.totalBytesWritten

    private suspend fun receiver() {
        try {
            while (true) {
                val bytes = recvPacket()
                val type = bytes.readInt()

                if ((state.isWaiting() && type != 0) || (state.isConnected() && type == 0))
                    break

                val serializer = PacketType.getSerializer(type)
                if (serializer == null) {
                    logger.info("unknown packet type $type")
                    continue
                }
                val packet = BlacknetDecoder(bytes).decode(serializer)
                if (packet == null) {
                    dos("deserialization failed")
                    continue
                }
                val connection = this
                launch {
                    packet.process(connection)
                }
            }
        } catch (e: ClosedReceiveChannelException) {
        } catch (e: CancellationException) {
        } catch (e: Throwable) {
            logger.error("Exception in receiver $remoteAddress", e)
        } finally {
            close()
        }
    }

    private suspend fun recvPacket(): ByteReadPacket {
        try {
            val size = readChannel.readInt()
            if (size > Node.getMaxPacketSize()) {
                logger.info("Too long packet $size max ${Node.getMaxPacketSize()} Disconnecting $remoteAddress")
                close()
            }
            return readChannel.readPacket(size)
        } catch (e: IOException) {
            throw ClosedReceiveChannelException(e.message)
        }
    }

    private suspend fun sender() {
        try {
            for (packet in sendChannel)
                writeChannel.writePacket(packet)
        } catch (e: ClosedWriteChannelException) {
        } catch (e: Throwable) {
            logger.error("Exception in sender $remoteAddress", e)
        } finally {
            close()
        }
    }

    fun sendPacket(p: Packet) {
        sendChannel.offer(p.build())
    }

    fun sendPacket(bytes: ByteReadPacket) {
        sendChannel.offer(bytes)
    }

    fun dos(reason: String) {
        dosScore++
        logger.info("DoS: $dosScore $reason $remoteAddress")
        if (dosScore >= 100)
            close()
    }

    fun close() {
        writeChannel.close()
        readChannel.cancel()
        Node.disconnected(this)
    }

    class PingRequest(val id: Int, val time: Long)

    enum class State {
        INCOMING_WAITING,
        INCOMING_CONNECTED,
        OUTGOING_WAITING,
        OUTGOING_CONNECTED;

        fun isConnected(): Boolean {
            return this == INCOMING_CONNECTED || this == OUTGOING_CONNECTED
        }

        fun isWaiting(): Boolean {
            return this == INCOMING_WAITING || this == OUTGOING_WAITING
        }
    }
}