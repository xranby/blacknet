/*
 * Copyright (c) 2018-2019 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.network

import com.google.common.io.Resources
import io.ktor.network.sockets.ServerSocket
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import kotlinx.coroutines.channels.ClosedSendChannelException
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.withLock
import mu.KotlinLogging
import ninja.blacknet.Config
import ninja.blacknet.Config.mintxfee
import ninja.blacknet.Config.upnp
import ninja.blacknet.Runtime
import ninja.blacknet.core.Accepted
import ninja.blacknet.core.Status
import ninja.blacknet.core.TxPool
import ninja.blacknet.crypto.BigInt
import ninja.blacknet.crypto.Hash
import ninja.blacknet.crypto.PoS
import ninja.blacknet.db.LedgerDB
import ninja.blacknet.db.PeerDB
import ninja.blacknet.packet.*
import ninja.blacknet.util.SynchronizedArrayList
import ninja.blacknet.util.SynchronizedHashSet
import ninja.blacknet.util.delay
import java.math.BigDecimal
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicLong
import kotlin.random.Random

private val logger = KotlinLogging.logger {}

object Node {
    const val DEFAULT_P2P_PORT: Short = 28453
    const val NETWORK_TIMEOUT = 90
    const val magic = 0x17895E7D
    const val version = 12
    const val minVersion = 9
    val nonce = Random.nextLong()
    val connections = SynchronizedArrayList<Connection>()
    val listenAddress = SynchronizedHashSet<Address>()
    var minTxFee = parseAmount(Config[mintxfee])
    private val nextPeerId = AtomicLong(1)

    init {
        if (!Config.regTest) {
            if (Config.netListen) {
                try {
                    listenOnIP()
                    if (Config[upnp])
                        Runtime.launch { UPnP.forward() }
                } catch (e: Throwable) {
                }
            }
            if (!Config.isDisabled(Network.TORv2))
                Runtime.launch { Network.listenOnTor() }
            if (!Config.isDisabled(Network.I2P))
                Runtime.launch { Network.listenOnI2P() }
            Runtime.launch { connector() }
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
        logger.info("Listening on $address")
        Runtime.launch {
            listenAddress.add(address)
            listener(server)
        }
    }

    private fun listenOnIP() {
        if (Network.IPv4.isDisabled() && Network.IPv6.isDisabled())
            return
        if (Network.IPv4.isDisabled())
            return listenOn(Address.IPv6_ANY(Config.netPort))
        listenOn(Address.IPv4_ANY(Config.netPort))
    }

    suspend fun connectTo(address: Address) {
        val connection = Network.connect(address)
        connections.mutex.withLock {
            connections.list.add(connection)
            connection.launch()
        }
        sendVersion(connection, nonce(address.network))
    }

    fun sendVersion(connection: Connection, nonce: Long) {
        val state = LedgerDB.state()
        val chain = ChainAnnounce(state.blockHash, state.cumulativeDifficulty)
        val v = Version(magic, version, Runtime.time(), nonce, UserAgent.string, minTxFee, chain)
        connection.sendPacket(v)
    }

    suspend fun announceChain(hash: Hash, cumulativeDifficulty: BigInt, source: Connection? = null): Int {
        val ann = ChainAnnounce(hash, cumulativeDifficulty)
        return broadcastPacket(ann) {
            it != source && it.lastChain.cumulativeDifficulty < cumulativeDifficulty
        }
    }

    suspend fun broadcastBlock(hash: Hash, bytes: ByteArray): Boolean {
        val (status, n) = ChainFetcher.stakedBlock(hash, bytes)
        if (status == Accepted) {
            if (!Config.regTest)
                logger.info("Announced to $n peers")
            return true
        } else {
            logger.info("$status block $hash")
            return false
        }
    }

    suspend fun broadcastTx(hash: Hash, bytes: ByteArray): Status {
        val currTime = Runtime.time()
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
        val toSend = ArrayList<Hash>(unfiltered.size)
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

    private suspend fun timeOffset(): Long = connections.mutex.withLock {
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

        if (timeOffset >= PoS.TIME_SLOT || timeOffset <= -PoS.TIME_SLOT)
            return listOf("Please check your system clock. Many peers report different time.")

        return emptyList()
    }

    private suspend fun broadcastPacket(packet: Packet, filter: (Connection) -> Boolean = { true }): Int {
        logger.debug { "Broadcasting ${packet.getType()}" }
        var n = 0
        val bytes = packet.build()
        connections.forEach {
            if (it.state.isConnected() && filter(it)) {
                try {
                    it.sendPacket(bytes.copy())
                    n += 1
                } catch (e: ClosedSendChannelException) {
                    //FIXME 骂人用语
                }
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
        return if (incoming(true) < Config.incomingConnections)
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

    private suspend fun connector() {
        if (PeerDB.isLow()) {
            addBuiltinPeers()
        }

        while (true) {
            val n = Config.outgoingConnections - outgoing()
            if (n <= 0) {
                delay(NETWORK_TIMEOUT)
                continue
            }

            val filter = connections.map { it.remoteAddress }.plus(listenAddress.toList())

            val addresses = PeerDB.getCandidates(n, filter)
            if (addresses.isEmpty()) {
                logger.info("Don't have candidates in PeerDB. ${outgoing()} connections, max ${Config.outgoingConnections}")
                if (!addBuiltinPeers()) {
                    logger.info("Z-z-z")
                    delay(PeerDB.DELAY)
                }
                continue
            }

            val currTime = Runtime.time()

            addresses.forEach { address ->
                Runtime.launch {
                    try {
                        connectTo(address)
                    } catch (e: Throwable) {
                        PeerDB.failed(address, currTime)
                    }
                }
            }

            delay(NETWORK_TIMEOUT)
        }
    }

    private suspend fun addBuiltinPeers(): Boolean {
        val list = Resources.readLines(Resources.getResource("peers.txt"), Charsets.UTF_8)

        val peers = ArrayList<Address>(list.size)
        for (i in list) {
            val address = Network.parse(i, DEFAULT_P2P_PORT)!!
            peers.add(address)
        }

        val added = PeerDB.add(peers, Address.LOOPBACK, true)

        if (added > 0) {
            logger.info("Added $added built-in peer addresses to db")
            return true
        } else {
            return false
        }
    }

    private fun parseAmount(string: String): Long {
        val n = (BigDecimal(string) * BigDecimal(PoS.COIN)).longValueExact()
        if (n < 0) throw RuntimeException("Negative amount")
        return n
    }
}
