/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.network

import io.ktor.network.sockets.ASocket
import io.ktor.utils.io.*
import io.ktor.utils.io.core.ByteReadPacket
import io.ktor.utils.io.core.readInt
import io.ktor.utils.io.errors.IOException
import java.math.BigInteger
import kotlin.coroutines.CoroutineContext
import kotlin.random.Random
import kotlinx.atomicfu.atomic
import kotlinx.coroutines.*
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ClosedReceiveChannelException
import kotlinx.coroutines.sync.withLock
import mu.KotlinLogging
import ninja.blacknet.Config
import ninja.blacknet.Runtime
import ninja.blacknet.core.currentTimeMillis
import ninja.blacknet.core.currentTimeSeconds
import ninja.blacknet.db.PeerDB
import ninja.blacknet.network.packet.*
import ninja.blacknet.serialization.bbf.binaryFormat
import ninja.blacknet.util.SynchronizedArrayList

private val logger = KotlinLogging.logger {}

class Connection(
        private val socket: ASocket,
        private val readChannel: ByteReadChannel,
        private val writeChannel: ByteWriteChannel,
        val remoteAddress: Address,
        val localAddress: Address,
        var state: State
) : CoroutineScope {
    val job = Job()
    override val coroutineContext: CoroutineContext = Runtime.coroutineContext + job

    private val closed = atomic(false)
    private val dosScore = atomic(0)
    private val sendChannel: Channel<ByteReadPacket> = Channel(Channel.UNLIMITED)
    private val inventoryToSend = SynchronizedArrayList<ByteArray>(Inventory.SEND_MAX)
    val connectedAt = currentTimeSeconds()

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
    var pingRequest: Pair<Int, Long>? = null
    @Volatile
    var requestedDifficulty: BigInteger = BigInteger.ZERO

    inline val requestedBlocks: Boolean
        get() = requestedDifficulty != BigInteger.ZERO

    var peerId: Long = 0
    var version: Int = 0
    var agent: String = ""
    var feeFilter: Long = 0
    var timeOffset: Long = 0

    fun launch() {
        launch { pinger() }
        launch { peerAnnouncer() }
        launch { inventoryBroadcaster() }
        launch { receiver() }
        launch { sender() }
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
                    val serializer = PacketType.getSerializer(type)
                    binaryFormat.decodeFromPacket(serializer, bytes)
                } catch (e: Throwable) {
                    dos("Deserialization failed: ${e.message}")
                    continue
                }
                logger.debug { "Received ${packet::class.simpleName} from ${debugName()}" }
                packet.process(this)
            }
        } catch (e: ClosedReceiveChannelException) {
        } catch (e: CancellationException) {
        } catch (e: IOException) {
        } catch (e: Throwable) {
            logger.error("Exception in receiver ${debugName()}", e)
        } finally {
            close()
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
        val result = readChannel.readPacket(size, 0)
        lastPacketTime = currentTimeMillis()
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
            close()
        }
    }

    suspend fun inventory(inv: ByteArray) = inventoryToSend.mutex.withLock {
        inventoryToSend.list.add(inv)
        if (inventoryToSend.list.size == Inventory.SEND_MAX) {
            sendInventoryImpl(currentTimeMillis())
        }
    }

    suspend fun inventory(inv: ArrayList<ByteArray>): Unit = inventoryToSend.mutex.withLock {
        val newSize = inventoryToSend.list.size + inv.size
        if (newSize < Inventory.SEND_MAX) {
            inventoryToSend.list.addAll(inv)
        } else if (newSize > Inventory.SEND_MAX) {
            val n = Inventory.SEND_MAX - inventoryToSend.list.size
            for (i in 0 until n)
                inventoryToSend.list.add(inv[i])
            sendInventoryImpl(currentTimeMillis())
            for (i in n until inv.size)
                inventoryToSend.list.add(inv[i])
        } else {
            inventoryToSend.list.addAll(inv)
            sendInventoryImpl(currentTimeMillis())
        }
    }

    private suspend fun sendInventory(time: Long) = inventoryToSend.mutex.withLock {
        if (inventoryToSend.list.size != 0) {
            sendInventoryImpl(time)
        }
    }

    private fun sendInventoryImpl(time: Long) {
        sendPacket(PacketType.Inventory, Inventory(inventoryToSend.list))
        inventoryToSend.list.clear()
        lastInvSentTime = time
    }

    fun sendPacket(type: PacketType, packet: Packet) {
        logger.debug { "Sending $type to ${debugName()}" }
        sendChannel.offer(buildPacket(type, packet))
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
        return dosScore.value
    }

    fun close() {
        if (closed.compareAndSet(false, true)) {
            socket.close()
            readChannel.cancel()
            writeChannel.close()
            Runtime.launch {
                Node.connections.remove(this@Connection)

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

                cancel()
                sendChannel.cancel()
                job.cancel()
            }
        }
    }

    fun isClosed(): Boolean {
        return closed.value
    }

    fun debugName(): String {
        return if (Config.instance.logips)
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
            delay(Random.nextLong(Node.NETWORK_TIMEOUT))
            sendPing()
        } else {
            close()
            return
        }

        while (true) {
            delay(Node.NETWORK_TIMEOUT)

            if (pingRequest == null) {
                if (currentTimeMillis() > lastPacketTime + Node.NETWORK_TIMEOUT) {
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
        pingRequest = Pair(challenge, currentTimeMillis())
        sendPacket(PacketType.Ping, Ping(challenge))
    }

    private suspend fun peerAnnouncer() {
        delay(Random.nextLong(10 * 60 * 1000L, 20 * 60 * 1000L))

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

            sendPacket(PacketType.Peers, Peers(randomPeers))

            delay(Random.nextLong(4 * 60 * 60 * 1000L, 20 * 60 * 60 * 1000L))
        }
    }

    private suspend fun inventoryBroadcaster() {
        while (!state.isConnected()) {
            delay(Inventory.SEND_TIMEOUT)
        }
        while (true) {
            val currTime = currentTimeMillis()
            if (currTime >= lastInvSentTime + Inventory.SEND_TIMEOUT) {
                sendInventory(currTime)
            }
            delay(Inventory.SEND_TIMEOUT)
        }
    }
}
