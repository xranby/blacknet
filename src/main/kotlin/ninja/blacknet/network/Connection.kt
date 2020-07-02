/*
 * Copyright (c) 2018-2019 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.network

import io.ktor.network.sockets.ASocket
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ClosedReceiveChannelException
import kotlinx.coroutines.io.*
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.withLock
import kotlinx.io.IOException
import kotlinx.io.core.ByteReadPacket
import mu.KotlinLogging
import ninja.blacknet.Config
import ninja.blacknet.Runtime
import ninja.blacknet.core.DataType
import ninja.blacknet.crypto.Hash
import ninja.blacknet.db.PeerDB
import ninja.blacknet.packet.*
import ninja.blacknet.util.SynchronizedArrayList
import ninja.blacknet.util.delay
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.random.Random

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
    private val inventoryToSend = SynchronizedArrayList<Hash>(Inventory.SEND_MAX)
    val connectedAt = Runtime.time()

    private var pinger: Job? = null
    private var peerAnnouncer: Job? = null
    private var inventoryBroadcaster: Job? = null

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
    var lastPingTime: Long = 0
    @Volatile
    var lastInvSentTime: Long = 0
    @Volatile
    var ping: Long = 0
    @Volatile
    internal var pingRequest: Pair<Int, Long>? = null
    @Volatile
    internal var requestedBlocks: Boolean = false

    var peerId: Long = 0
    var version: Int = 0
    var agent: String = ""
    var feeFilter: Long = 0
    var timeOffset: Long = 0

    fun launch() {
        pinger = Runtime.launch { pinger() }
        peerAnnouncer = Runtime.launch { peerAnnouncer() }
        inventoryBroadcaster = Runtime.launch { inventoryBroadcaster() }
        Runtime.launch { receiver() }
        Runtime.launch { sender() }
    }

    private suspend fun receiver() {
        try {
            while (true) {
                val bytes = recvPacket()
                val type = bytes.readInt()

                if (state.isConnected()) {
                    if (type == PacketType.Version.ordinal)
                        break
                } else {
                    if (type != PacketType.Version.ordinal)
                        break
                }

                val packet = try {
                    Packet.deserialize(type, bytes)
                } catch (e: Throwable) {
                    dos("Deserialization failed: ${e.message}")
                    continue
                }
                logger.debug { "Received ${packet.getType()} from ${debugName()}" }
                packet.process(this)
            }
        } catch (e: ClosedReceiveChannelException) {
        } catch (e: CancellationException) {
        } catch (e: IOException) {
        } catch (e: Throwable) {
            logger.error("Exception in receiver ${debugName()}", e)
        } finally {
            close(false)
        }
    }

    private suspend fun recvPacket(): ByteReadPacket {
        val size = readChannel.readInt()
        if (size > Node.getMaxPacketSize()) {
            if (state.isConnected()) {
                logger.info("Too long packet $size max ${Node.getMaxPacketSize()} Disconnecting ${debugName()}")
            }
            close()
        }
        val result = readChannel.readPacket(size)
        lastPacketTime = Runtime.time()
        totalBytesRead += size + 4
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
            logger.error("Exception in sender ${debugName()}", e)
        } finally {
            close(false)
            closeSocket()
        }
    }

    suspend fun inventory(inv: Hash) = inventoryToSend.mutex.withLock {
        inventoryToSend.list.add(inv)
        if (inventoryToSend.list.size == Inventory.SEND_MAX) {
            sendInventoryImpl(Runtime.time())
        }
    }

    suspend fun inventory(inv: ArrayList<Hash>): Unit = inventoryToSend.mutex.withLock {
        val newSize = inventoryToSend.list.size + inv.size
        if (newSize < Inventory.SEND_MAX) {
            inventoryToSend.list.addAll(inv)
        } else if (newSize > Inventory.SEND_MAX) {
            val n = Inventory.SEND_MAX - inventoryToSend.list.size
            for (i in 0 until n)
                inventoryToSend.list.add(inv[i])
            sendInventoryImpl(Runtime.time())
            for (i in n until inv.size)
                inventoryToSend.list.add(inv[i])
        } else {
            inventoryToSend.list.addAll(inv)
            sendInventoryImpl(Runtime.time())
        }
    }

    private suspend fun sendInventory(time: Long) = inventoryToSend.mutex.withLock {
        if (inventoryToSend.list.size != 0) {
            sendInventoryImpl(time)
        }
    }

    private fun sendInventoryImpl(time: Long) {
        if (version >= Inventory.MIN_VERSION)
            sendPacket(Inventory(inventoryToSend.list))
        else
            sendPacket(InventoryV1(inventoryToSend.list.map { Pair(DataType.Transaction, it) }))
        inventoryToSend.list.clear()
        lastInvSentTime = time
    }

    fun sendPacket(packet: Packet) {
        logger.debug { "Sending ${packet.getType()} to ${debugName()}" }
        sendChannel.offer(packet.build())
    }

    internal fun sendPacket(bytes: ByteReadPacket) {
        sendChannel.offer(bytes)
    }

    fun dos(reason: String) {
        val score = dosScore.incrementAndGet()
        if (score == 100)
            close()
        logger.info("$reason ${debugName()} DoS $score")
    }

    fun dosScore(): Int {
        return dosScore.get()
    }

    fun close(cancel: Boolean = true) {
        if (closed.compareAndSet(false, true)) {
            Runtime.launch {
                Node.connections.remove(this@Connection)

                pinger?.cancel()
                peerAnnouncer?.cancel()
                inventoryBroadcaster?.cancel()

                when (state) {
                    State.INCOMING_CONNECTED, State.OUTGOING_CONNECTED -> {
                        ChainFetcher.disconnected(this@Connection)
                    }
                    State.OUTGOING_WAITING, State.PROBER_WAITING -> {
                        PeerDB.failed(remoteAddress, connectedAt)
                    }
                    State.INCOMING_WAITING, State.PROBER_CONNECTED -> {
                    }
                }

                if (cancel)
                    sendChannel.cancel()
                else
                    sendChannel.close()
            }
        }
    }

    private fun closeSocket() {
        socket.close()
    }

    fun isClosed(): Boolean {
        return closed.get()
    }

    fun debugName(): String {
        return if (Config.logIPs)
            remoteAddress.toString()
        else
            "peer $peerId"
    }

    enum class State {
        INCOMING_CONNECTED,
        INCOMING_WAITING,
        OUTGOING_CONNECTED,
        OUTGOING_WAITING,
        PROBER_CONNECTED,
        PROBER_WAITING,
        ;

        fun isConnected(): Boolean {
            return this == INCOMING_CONNECTED || this == OUTGOING_CONNECTED
                    // this == PROBER_CONNECTED
        }

        fun isIncoming(): Boolean {
            return this == INCOMING_CONNECTED || this == INCOMING_WAITING
        }

        fun isOutgoing(): Boolean {
            return this == OUTGOING_CONNECTED || this == OUTGOING_WAITING
                    || this == PROBER_CONNECTED || this == PROBER_WAITING
        }
    }

    private suspend fun pinger() {
        delay(Node.NETWORK_TIMEOUT)

        if (state.isConnected()) {
            delay(Random.nextInt(Node.NETWORK_TIMEOUT))
            sendPing()
        } else {
            close()
            return
        }

        while (true) {
            delay(Node.NETWORK_TIMEOUT)

            if (pingRequest == null) {
                if (Runtime.time() > lastPacketTime + Node.NETWORK_TIMEOUT) {
                    sendPing()
                }
            } else {
                logger.info("Disconnecting ${debugName()} on ping timeout")
                close()
                return
            }
        }
    }

    private fun sendPing() {
        val challenge = Random.nextInt()
        pingRequest = Pair(challenge, Runtime.timeMilli())
        sendPacket(Ping(challenge))
    }

    private suspend fun peerAnnouncer() {
        delay(10 * 60 + Random.nextInt(10 * 60))

        while (true) {
            val n = Random.nextInt(Peers.MAX) + 1

            val randomPeers = PeerDB.getRandom(n)
            if (randomPeers.size == 0)
                continue

            val myAddress = Node.listenAddress.filterToList { !it.isLocal() && !it.isPrivate() && !PeerDB.contains(it) }
            if (myAddress.size != 0) {
                val i = Random.nextInt(randomPeers.size * 4)
                if (i < randomPeers.size) {
                    randomPeers[i] = myAddress[Random.nextInt(myAddress.size)]
                    logger.info("Whispering ${randomPeers[i].debugName()} to ${debugName()}")
                }
            }

            if (version >= Peers.MIN_VERSION)
                sendPacket(Peers(randomPeers))
            else
                sendPacket(PeersV1(randomPeers.map { AddressV1(it) }))

            delay(4 * 60 * 60 + Random.nextInt(20 * 60 * 60))
        }
    }

    private suspend fun inventoryBroadcaster() {
        while (!state.isConnected()) {
            delay(Inventory.SEND_TIMEOUT)
        }
        while (true) {
            val currTime = Runtime.time()
            if (currTime >= lastInvSentTime + Inventory.SEND_TIMEOUT) {
                sendInventory(currTime)
            }
            delay(Inventory.SEND_TIMEOUT)
        }
    }
}
