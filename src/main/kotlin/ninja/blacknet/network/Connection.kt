/*
 * Copyright (c) 2018 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.network

import io.ktor.network.sockets.ASocket
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ClosedReceiveChannelException
import kotlinx.coroutines.io.*
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.withLock
import kotlinx.io.IOException
import kotlinx.io.core.ByteReadPacket
import mu.KotlinLogging
import ninja.blacknet.core.DataType
import ninja.blacknet.serialization.BinaryDecoder
import ninja.blacknet.util.SynchronizedArrayList
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

private val logger = KotlinLogging.logger {}

class Connection(
        private val socket: ASocket,
        private val readChannel: ByteReadChannel,
        private val writeChannel: ByteWriteChannel,
        val remoteAddress: Address,
        val localAddress: Address,
        var state: State
) {
    private val closed = AtomicBoolean()
    private val dosScore = AtomicInteger(0)
    private val sendChannel: Channel<ByteReadPacket> = Channel(Channel.UNLIMITED)
    private val inventoryToSend = SynchronizedArrayList<InvType>()
    val connectedAt = Node.time()

    @Volatile
    var lastPacketTime: Long = 0
    @Volatile
    var totalBytesRead: Long = 0
    @Volatile
    var totalBytesWritten: Long = 0
    @Volatile
    var lastChain: ChainAnnounce = ChainAnnounce.GENESIS
    @Volatile
    var lastBlockTime: Long = 0
    @Volatile
    var lastTxTime: Long = 0
    @Volatile
    var lastInvSentTime: Long = 0
    @Volatile
    var ping: Long = 0
    @Volatile
    internal var pingRequest: PingRequest? = null

    var version: Int = 0
    var agent: String = ""
    var feeFilter: Long = 0
    var timeOffset: Long = 0

    fun launch(scope: CoroutineScope) {
        scope.launch { receiver() }
        scope.launch { sender() }
    }

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
                val packet = BinaryDecoder(bytes).decode(serializer)
                if (packet == null) {
                    dos("deserialization failed")
                    continue
                }
                logger.debug { "Received ${packet.getType()} from $remoteAddress" }
                packet.process(this)
            }
        } catch (e: ClosedReceiveChannelException) {
        } catch (e: CancellationException) {
        } catch (e: IOException) {
        } catch (e: Throwable) {
            logger.error("Exception in receiver $remoteAddress", e)
        } finally {
            close(false)
        }
    }

    private suspend fun recvPacket(): ByteReadPacket {
        val size = readChannel.readInt()
        totalBytesRead += 4
        if (size > Node.getMaxPacketSize()) {
            if (state.isConnected()) {
                logger.info("Too long packet $size max ${Node.getMaxPacketSize()} Disconnecting $remoteAddress")
            }
            close()
        }
        val result = readChannel.readPacket(size)
        totalBytesRead += size
        lastPacketTime = Node.time()
        return result
    }

    private suspend fun sender() {
        try {
            for (packet in sendChannel) {
                val size = packet.remaining
                writeChannel.writePacket(packet)
                totalBytesWritten += size
            }
        } catch (e: ClosedWriteChannelException) {
        } catch (e: CancellationException) {
        } catch (e: Throwable) {
            logger.error("Exception in sender $remoteAddress", e)
        } finally {
            close(false)
            closeSocket()
        }
    }

    suspend fun inventory(inv: InvType) = inventoryToSend.mutex.withLock {
        inventoryToSend.list.add(inv)
        if (inventoryToSend.list.size == DataType.MAX_INVENTORY) {
            sendInventoryImpl(Node.time())
        }
    }

    suspend fun inventory(inv: InvList): Unit = inventoryToSend.mutex.withLock {
        val newSize = inventoryToSend.list.size + inv.size
        if (newSize < DataType.MAX_INVENTORY) {
            inventoryToSend.list.addAll(inv)
        } else if (newSize > DataType.MAX_INVENTORY) {
            sendInventoryImpl(Node.time())
            inventoryToSend.list.addAll(inv)
        } else {
            inventoryToSend.list.addAll(inv)
            sendInventoryImpl(Node.time())
        }
    }

    internal suspend fun sendInventory(time: Long) = inventoryToSend.mutex.withLock {
        if (inventoryToSend.list.size != 0) {
            sendInventoryImpl(time)
        }
    }

    private fun sendInventoryImpl(time: Long) {
        sendPacket(Inventory(inventoryToSend.list))
        inventoryToSend.list.clear()
        lastInvSentTime = time
    }

    fun sendPacket(packet: Packet) {
        logger.debug { "Sending ${packet.getType()} to $remoteAddress" }
        sendChannel.offer(packet.build())
    }

    internal fun sendPacket(bytes: ByteReadPacket) {
        sendChannel.offer(bytes)
    }

    fun dos(reason: String) {
        val score = dosScore.incrementAndGet()
        logger.info("DoS: $score $reason $remoteAddress")
        if (score == 100)
            close()
    }

    fun dosScore(): Int {
        return dosScore.get()
    }

    fun close(cancel: Boolean = true) {
        if (closed.compareAndSet(false, true)) {
            if (cancel)
                sendChannel.cancel()
            else
                sendChannel.close()
            Node.launch {
                ChainFetcher.disconnected(this@Connection)
                Node.connections.remove(this@Connection)
            }
        }
    }

    private fun closeSocket() {
        socket.close()
    }

    fun isClosed(): Boolean {
        return closed.get()
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