/*
 * Copyright (c) 2018-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.network

import io.ktor.network.sockets.ServerSocket
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import java.math.BigInteger
import java.net.InetSocketAddress
import kotlin.random.Random
import kotlinx.atomicfu.atomic
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.withLock
import mu.KotlinLogging
import ninja.blacknet.regtest
import ninja.blacknet.Config
import ninja.blacknet.Runtime
import ninja.blacknet.core.*
import ninja.blacknet.crypto.PoS
import ninja.blacknet.db.LedgerDB
import ninja.blacknet.db.PeerDB
import ninja.blacknet.network.packet.*
import ninja.blacknet.util.HashSet
import ninja.blacknet.util.SynchronizedArrayList
import ninja.blacknet.util.SynchronizedHashSet

private val logger = KotlinLogging.logger {}

object Node {
    const val DEFAULT_P2P_PORT: Short = 28453
    const val NETWORK_TIMEOUT = 90 * 1000L
    const val magic = 0x17895E7D
    const val version = 13
    const val minVersion = 12
    val nonce = Random.nextLong()
    val connections = SynchronizedArrayList<Connection>()
    val listenAddress = SynchronizedHashSet<Address>()
    private val nextPeerId = atomic(1L)

    init {
        if (!regtest) {
            if (Config.instance.listen) {
                try {
                    listenOnIP()
                    if (Config.instance.upnp) {
                        Runtime.launch { UPnP.forward() }
                    }
                } catch (e: Throwable) {
                }
            }
            if (Config.instance.tor) {
                if (!Config.instance.listen || Network.IPv4.isDisabled() && Network.IPv6.isDisabled())
                    listenOn(Network.LOOPBACK)
                Runtime.rotate(Network.Companion::listenOnTor)
            }
            if (Config.instance.i2p) {
                Runtime.rotate(Network.Companion::listenOnI2P)
            }
            repeat(Config.instance.outgoingconnections) {
                Runtime.rotate(::connector)
            }
            Runtime.rotate(::prober)
        }
    }

    fun newPeerId(): Long {
        return nextPeerId.getAndIncrement()
    }

    private fun nonce(network: Network): Long = when (network) {
        Network.IPv4, Network.IPv6 -> nonce
        else -> Random.nextLong()
    }

    suspend fun outgoing(): Int {
        return connections.count {
            when (it.state) {
                Connection.State.OUTGOING_CONNECTED -> true
                else -> false
            }
        }
    }

    suspend fun incoming(includeWaiting: Boolean = false): Int {
        return if (includeWaiting)
            connections.count {
                when (it.state) {
                    Connection.State.INCOMING_CONNECTED -> true
                    Connection.State.INCOMING_WAITING -> true
                    else -> false
                }
            }
        else
            connections.count {
                when (it.state) {
                    Connection.State.INCOMING_CONNECTED -> true
                    else -> false
                }
            }
    }

    suspend fun connected(): Int {
        return connections.count {
            when (it.state) {
                Connection.State.INCOMING_CONNECTED -> true
                Connection.State.OUTGOING_CONNECTED -> true
                else -> false
            }
        }
    }

    suspend fun isOffline(): Boolean {
        return connections.find { it.state.isConnected() } == null
    }

    fun getMaxPacketSize(): Int {
        return LedgerDB.state().maxBlockSize + PoS.BLOCK_RESERVED_SIZE
    }

    fun getMinPacketSize(): Int {
        return PoS.DEFAULT_MAX_BLOCK_SIZE + PoS.BLOCK_RESERVED_SIZE
    }

    fun isInitialSynchronization(): Boolean {
        return ChainFetcher.isSynchronizing() && PoS.guessInitialSynchronization()
    }

    fun listenOn(address: Address) {
        val addr = when (address.network) {
            Network.IPv4, Network.IPv6 -> address.getSocketAddress()
            else -> throw NotImplementedError("Not implemented for " + address.network)
        }
        val server = aSocket(Network.selector).tcp().bind(addr)
        logger.info("Listening on ${address.debugName()}")
        Runtime.launch {
            listenAddress.add(address)
            listener(server)
        }
    }

    private fun listenOnIP() {
        if (Network.IPv4.isDisabled() && Network.IPv6.isDisabled())
            return
        if (Network.IPv4.isDisabled())
            return listenOn(Address.IPv6_ANY(Config.instance.port.toPort()))
        listenOn(Address.IPv4_ANY(Config.instance.port.toPort()))
    }

    suspend fun connectTo(address: Address, prober: Boolean = false): Connection {
        val connection = Network.connect(address, prober)
        connections.mutex.withLock {
            connections.list.add(connection)
            connection.launch()
        }
        sendVersion(connection, nonce(address.network), prober)
        return connection
    }

    fun sendVersion(connection: Connection, nonce: Long, prober: Boolean) {
        connection.sendPacket(PacketType.Version, if (prober) {
            Version(
                    magic,
                    version,
                    currentTimeSeconds(),
                    nonce,
                    UserAgent.prober,
                    Long.MAX_VALUE,
                    ChainAnnounce.GENESIS
            )
        } else {
            val state = LedgerDB.state()
            Version(
                    magic,
                    version,
                    currentTimeSeconds(),
                    nonce,
                    UserAgent.string,
                    TxPool.minFeeRate,
                    ChainAnnounce(state.blockHash, state.cumulativeDifficulty)
            )
        })
    }

    suspend fun announceChain(hash: ByteArray, cumulativeDifficulty: BigInteger, source: Connection? = null): Int {
        Staker.awaitsNextTimeSlot?.cancel()
        val ann = ChainAnnounce(hash, cumulativeDifficulty)
        return broadcastPacket(PacketType.ChainAnnounce, ann) {
            it != source && it.lastChain.cumulativeDifficulty < cumulativeDifficulty
        }
    }

    suspend fun broadcastBlock(hash: ByteArray, bytes: ByteArray): Boolean {
        val (status, n) = ChainFetcher.stakedBlock(hash, bytes)
        if (status == Accepted) {
            if (!regtest)
                logger.info("Announced to $n peers")
            return true
        } else {
            logger.info(status.toString())
            return false
        }
    }

    suspend fun broadcastTx(hash: ByteArray, bytes: ByteArray): Status {
        val currTime = currentTimeSeconds()
        val (status, fee) = TxPool.process(hash, bytes, currTime, false)
        if (status == Accepted) {
            connections.forEach {
                if (it.state.isConnected() && it.feeFilter <= fee)
                    it.inventory(hash)
            }
        }
        return status
    }

    suspend fun broadcastInv(unfiltered: UnfilteredInvList, source: Connection? = null): Int {
        var n = 0
        val toSend = ArrayList<ByteArray>(unfiltered.size)
        connections.forEach {
            if (it != source && it.state.isConnected()) {
                for (i in 0 until unfiltered.size) {
                    val (hash, fee) = unfiltered[i]
                    if (it.feeFilter <= fee)
                        toSend.add(hash)
                }
                if (toSend.size != 0) {
                    it.inventory(toSend)
                    toSend.clear()
                    n += 1
                }
            }
        }
        return n
    }

    private suspend inline fun timeOffset(): Long = connections.mutex.withLock {
        val size = connections.list.size
        return if (size >= 5) {
            val offsets = Array(size) { connections.list[it].timeOffset }
            offsets.sort()
            val median = offsets[size / 2]
            median
        } else {
            0
        }
    }

    suspend fun warnings(): List<String> {
        val timeOffset = timeOffset()

        return if (timeOffset >- PoS.TIME_SLOT && timeOffset <+ PoS.TIME_SLOT)
            emptyList()
        else
            listOf("Please check your system clock. Many peers report different time.")
    }

    private suspend fun broadcastPacket(type: PacketType, packet: Packet, filter: (Connection) -> Boolean = { true }): Int {
        logger.debug { "Broadcasting $type" }
        var n = 0
        val bytes = buildPacket(type, packet)
        connections.forEach {
            if (it.state.isConnected() && filter(it)) {
                it.sendPacket(bytes.copy())
                n += 1
            }
        }
        bytes.release()
        return n
    }

    private suspend fun listener(server: ServerSocket) {
        while (true) {
            val socket = server.accept()
            val remoteAddress = Network.address(socket.remoteAddress as InetSocketAddress)
            val localAddress = Network.address(socket.localAddress as InetSocketAddress)
            if (!localAddress.isLocal())
                listenAddress.add(localAddress)
            val connection = Connection(socket, socket.openReadChannel(), socket.openWriteChannel(true), remoteAddress, localAddress, Connection.State.INCOMING_WAITING)
            addConnection(connection)
        }
    }

    suspend fun addConnection(connection: Connection) {
        if (!haveSlot()) {
            logger.info("Too many connections, dropping ${connection.debugName()}")
            connection.close()
            return
        }
        connections.mutex.withLock {
            connections.list.add(connection)
            connection.launch()
        }
    }

    private suspend fun haveSlot(): Boolean {
        return if (incoming(true) < Config.instance.incomingconnections)
            true
        else
            evictConnection()
    }

    private suspend fun evictConnection(): Boolean {
        val candidates = connections.filter { it.state.isIncoming() }.asSequence()
                .sortedBy { if (it.ping != 0L) it.ping else Long.MAX_VALUE }.drop(4)
                .sortedByDescending { it.lastTxTime }.drop(4)
                .sortedByDescending { it.lastBlockTime }.drop(4)
                .sortedBy { it.connectedAt }.drop(4)
                .toMutableList()

        //TODO network groups

        if (candidates.isEmpty())
            return false

        val connection = candidates.random()
        logger.info("Evicting ${connection.debugName()}")
        connection.close()
        return true
    }

    private suspend fun getFilter(): HashSet<Address> {
        val filter = HashSet<Address>(expectedSize = connections.size() + listenAddress.size())
        connections.forEach { filter.add(it.remoteAddress) }
        listenAddress.forEach { filter.add(it) }
        return filter
    }

    private suspend fun connector() {
        val filter = getFilter()
        val address = PeerDB.getCandidate { address, _ -> !filter.contains(address) }
        if (address == null) {
            logger.info("Don't have candidates in PeerDB. ${outgoing()} connections, max ${Config.instance.outgoingconnections}")
            delay(15 * 60 * 1000L)
            return
        }

        val time = currentTimeMillis()

        try {
            connectTo(address).job.join()
        } catch (e: Throwable) {
            PeerDB.failed(address, time / 1000L)
        }

        val x = 4 * 1000L - (currentTimeMillis() - time)
        if (x > 0L)
            delay(x) // 請在繼續之前等待或延遲
    }

    /**
     * Peer network prober is a tool that periodically tries to establish an
     * outgoing connection in order to provide statistic for the peer database
     * prober.
     */
    private suspend fun prober() {
        delay(4 * 60 * 1000L)

        // Await peer network address announce
        if (PeerDB.size() < PeerDB.MAX_SIZE / 2)
            return

        // Await while connectors are working
        if (outgoing() < Config.instance.outgoingconnections)
            return

        val filter = getFilter()
        val time = currentTimeMillis()
        val address = PeerDB.getCandidate { address, entry ->
            (time / 1000L > entry.lastTry + 4 * 60 * 60) && !filter.contains(address)
        } ?: return

        try {
            connectTo(address, prober = true)
        } catch (e: Throwable) {
            PeerDB.failed(address, time / 1000L)
        }
    }
}
