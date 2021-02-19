/*
 * Copyright (c) 2018-2020 Pavel Vasin
 * Copyright (c) 2018 Blacknet Team
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.db

import java.util.concurrent.ConcurrentHashMap
import kotlin.math.exp
import kotlin.math.max
import kotlin.math.min
import kotlin.math.pow
import kotlin.random.Random
import kotlinx.coroutines.delay
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.*
import mu.KotlinLogging
import ninja.blacknet.regtest
import ninja.blacknet.Runtime
import ninja.blacknet.contract.BAppIdSerializer
import ninja.blacknet.core.currentTimeSeconds
import ninja.blacknet.logging.error
import ninja.blacknet.network.Address
import ninja.blacknet.network.AddressV1
import ninja.blacknet.network.Network
import ninja.blacknet.network.Node
import ninja.blacknet.serialization.VarIntSerializer
import ninja.blacknet.serialization.bbf.BinaryDecoder
import ninja.blacknet.serialization.bbf.BinaryEncoder
import ninja.blacknet.serialization.bbf.binaryFormat
import ninja.blacknet.util.HashMap
import ninja.blacknet.util.HashSet
import ninja.blacknet.util.Resources

private val logger = KotlinLogging.logger {}

object PeerDB {
    const val MAX_SIZE = 8192
    private const val VERSION = 4
    private val peers = ConcurrentHashMap<Address, Entry>((MAX_SIZE / 0.75f + 1.0f).toInt())
    private val STATE_KEY = DBKey(0x80.toByte(), 0)
    private val VERSION_KEY = DBKey(0x81.toByte(), 0)

    private fun setVersion(batch: LevelDB.WriteBatch) {
        val versionBytes = binaryFormat.encodeToByteArray(VarIntSerializer, VERSION)
        batch.put(VERSION_KEY, versionBytes)
    }

    init {
        val stateBytes = LevelDB.get(STATE_KEY)
        val versionBytes = LevelDB.get(VERSION_KEY)

        val version = if (versionBytes != null) {
            binaryFormat.decodeFromByteArray(VarIntSerializer, versionBytes)
        } else {
            1
        }

        val hashMap = if (version == VERSION) {
            if (stateBytes != null) {
                binaryFormat.decodeFromByteArray(MapSerializer(Address.serializer(), Entry.serializer()), stateBytes)
            } else {
                emptyMap<Address, Entry>()
            }
        } else if (version in 1 until VERSION) {
            val batch = LevelDB.createWriteBatch()

            val updatedHashMap = if (stateBytes != null) {
                logger.info("Upgrading PeerDB...")
                val result = HashMap<Address, Entry>(expectedSize = MAX_SIZE)
                try {
                    if (version == 3) {
                        val stateV3 = binaryFormat.decodeFromByteArray(MapSerializer(Address.serializer(), EntryV3.serializer()), stateBytes)
                        stateV3.forEach { (address, entryV3) ->
                            result.put(address, Entry(entryV3))
                        }
                    } else if (version == 2) {
                        val stateV2 = binaryFormat.decodeFromByteArray(MapSerializer(AddressV1.serializer(), EntryV2.serializer()), stateBytes)
                        stateV2.forEach { (addressV1, entryV2) ->
                            result.put(Address(addressV1), Entry(entryV2))
                        }
                    } else if (version == 1) {
                        val stateV1 = binaryFormat.decodeFromByteArray(MapSerializer(AddressV1.serializer(), EntryV1.serializer()), stateBytes)
                        stateV1.forEach { (addressV1, entryV1) ->
                            result.put(Address(addressV1), Entry(entryV1))
                        }
                    }
                } catch (e: Throwable) {
                    logger.error(e)
                }
                result
            } else {
                emptyMap<Address, Entry>()
            }

            setVersion(batch)

            if (updatedHashMap.isEmpty())
                batch.write()
            else
                commitImpl(updatedHashMap, batch, false)

            updatedHashMap
        } else {
            throw RuntimeException("Unknown database version $version")
        }

        logger.info("Loaded ${hashMap.size} peer addresses")

        peers.putAll(hashMap)

        if (peers.size < 100) {
            val added = add(listBuiltinPeers(), Network.LOOPBACK)
            if (added > 0) {
                logger.info("Added $added built-in peer addresses to db")
            }
        }

        Runtime.addShutdownHook {
            commit(true)
        }
        Runtime.rotate(::prober)
    }

    private fun listBuiltinPeers(): List<Address> {
        return if (regtest)
            emptyList()
        else
            Resources.lines(PeerDB::class.java, "peers.txt", Charsets.UTF_8)
                    .map {
                        Network.parse(it, Node.DEFAULT_P2P_PORT) ?: throw RuntimeException("Failed to parse $it")
                    }
    }

    fun size(): Int {
        return peers.size
    }

    fun isEmpty(): Boolean {
        return peers.isEmpty()
    }

    fun connected(address: Address, time: Long, userAgent: String, prober: Boolean) {
        if (address.isLocal()) return
        val entry = peers.get(address)
        if (entry != null)
            entry.connected(time, userAgent, prober)
        else
            peers.put(address, Entry.newConnected(time, userAgent))
    }

    suspend fun failed(address: Address, time: Long) {
        if (Node.isOffline()) return
        peers.get(address)?.failed(time)
    }

    fun batcherAnnounce(address: Address, announce: List<ByteArray>): Unit {
        peers.get(address)?.stat?.batcher?.let { batcher ->
            announce.forEach { id ->
                if (BAppDB.isInteresting(id)) {
                    batcher.add(id)
                }
            }
        }
    }

    fun getBatchers(id: ByteArray): List<Address> {
        val result = ArrayList<Address>(peers.size)
        peers.forEach { (address, entry) -> if (entry.stat?.batcher?.contains(id) == true) result.add(address) }
        return result
    }

    fun getAll(): List<Pair<Address, Entry>> {
        return peers.toList()
    }

    fun getSeed(): List<Address> {
        val result = ArrayList<Address>(peers.size)
        peers.forEach { (address, entry) -> address.port == Node.DEFAULT_P2P_PORT && entry.isReliable() }
        return result
    }

    fun getCandidate(predicate: (Address, Entry) -> Boolean): Address? {
        val candidates = ArrayList<Pair<Address, Float>>(peers.size)
        val currTime = currentTimeSeconds()
        peers.forEach { (address, entry) ->
            if (predicate(address, entry))
                candidates.add(Pair(address, entry.chance(currTime)))
        }
        if (candidates.isNotEmpty()) {
            while (true) {
                val (address, chance) = candidates.random()
                if (chance > Random.nextFloat())
                    return address
            }
        } else {
            return null
        }
    }

    fun getRandom(n: Int): ArrayList<Address> {
        val candidates = ArrayList<Address>(peers.size)
        peers.forEach { (address, _) -> candidates.add(address) }
        candidates.shuffle()
        val x = min(candidates.size, n)
        val result = ArrayList<Address>(x)
        for (i in 0 until x)
            result.add(candidates[i])
        return result
    }

    fun add(newPeers: List<Address>, from: Address, force: Boolean = false): Int {
        var added = 0
        var i = 0
        val newPeersSize = newPeers.size
        val nToAdd = if (!force) {
            val freeSlots = max(MAX_SIZE - peers.size, 0)
            min(newPeersSize, freeSlots)
        } else {
            newPeersSize
        }
        while (i < newPeersSize && added < nToAdd) {
            if (addImpl(newPeers[i], from))
                added += 1
            i += 1
        }
        return added
    }

    private fun addImpl(peer: Address, from: Address): Boolean {
        if (peer.isLocal())
            return false
        if (peer.isPrivate())
            return false
        if (peers.containsKey(peer))
            return false
        peers.put(peer, Entry.new(from))
        return true
    }

    fun contains(peer: Address): Boolean {
        return peers.containsKey(peer)
    }

    private suspend fun prober() {
        delay(1 * 60 * 60 * 1000L)

        // Await while node is offline
        if (Node.isOffline())
            return

        val toRemove = ArrayList<Address>()
        val currTime = currentTimeSeconds()
        peers.forEach { (address, entry) ->
            if (entry.isOld(currTime))
                toRemove.add(address)
        }
        if (!toRemove.isEmpty()) {
            toRemove.forEach { peers.remove(it) }
            val batch = LevelDB.createWriteBatch()
            commitImpl(peers, batch, false)
            logger.info("Probed ${toRemove.size} entries")
        }
    }

    private fun commit(sync: Boolean = false) {
        val batch = LevelDB.createWriteBatch()
        commitImpl(peers, batch, sync)
    }

    private fun commitImpl(map: Map<Address, Entry>, batch: LevelDB.WriteBatch, sync: Boolean) {
        val bytes = binaryFormat.encodeToByteArray(MapSerializer(Address.serializer(), Entry.serializer()), map)
        batch.put(STATE_KEY, bytes)
        batch.write(sync)
    }

    @Serializable
    class NetworkStat(
            var lastConnected: Long,
            var userAgent: String,
            val stat2H: UptimeStat,
            val stat8H: UptimeStat,
            val stat1D: UptimeStat,
            val stat1W: UptimeStat,
            val stat1M: UptimeStat,
            val batcher: HashSet<@Serializable(BAppIdSerializer::class) ByteArray>
    ) {
        constructor(lastConnected: Long, userAgent: String) : this(
                lastConnected,
                userAgent,
                UptimeStat(),
                UptimeStat(),
                UptimeStat(),
                UptimeStat(),
                UptimeStat(),
                HashSet(expectedSize = 0)
        )
        internal constructor(stat: NetworkStatV1) : this(stat.lastConnected, stat.userAgent, stat.stat2H, stat.stat8H, stat.stat1D, stat.stat1W, stat.stat1M, HashSet(expectedSize = 0))
    }

    @Serializable
    class Entry(
            val from: Address,
            var attempts: Int,
            var lastTry: Long,
            var stat: NetworkStat?
    ) {
        internal constructor(entry: EntryV1) : this(Address(entry.from), entry.attempts, entry.lastTry, null)
        internal constructor(entry: EntryV2) : this(Address(entry.from), entry.attempts, entry.lastTry, entry.stat?.let { NetworkStat(it) })
        internal constructor(entry: EntryV3) : this(entry.from, entry.attempts, entry.lastTry, entry.stat?.let { NetworkStat(it) })

        fun failed(time: Long) {
            stat?.let { updateUptimeStat(it, false, time) }
            attempts += 1
            lastTry = time
        }

        fun connected(time: Long, userAgent: String, prober: Boolean) {
            val stat = stat
            if (stat != null) {
                stat.lastConnected = time
                stat.userAgent = userAgent
                if (!prober)
                    stat.batcher.clear()
                updateUptimeStat(stat, true, time)
            } else {
                @Suppress("NAME_SHADOWING")
                val stat = NetworkStat(time, userAgent)
                updateUptimeStat(stat, true, time)
                this.stat = stat
            }
            attempts = 0
            lastTry = time
        }

        fun chance(time: Long): Float {
            val age = time - lastTry
            val chance = 0.66f.pow(min(attempts, 8))
            return if (age > 15 * 60)
                chance
            else
                chance * 0.01f
        }

        fun isNew(): Boolean {
            return stat == null && attempts == 0
        }

        fun isOld(currTime: Long): Boolean {
            val lastConnected = stat?.lastConnected ?: 0L

            if (lastConnected == 0L && attempts > 15)
                return true
            if (lastConnected != 0L && currTime - lastConnected > 15 * 24 * 60 * 60)
                return true

            return false
        }

        fun isReliable(): Boolean {
            val stat = stat ?: return false

            if (stat.stat2H.reliability > 0.85f && stat.stat2H.count > 2f) return true
            if (stat.stat8H.reliability > 0.70f && stat.stat8H.count > 4f) return true
            if (stat.stat1D.reliability > 0.55f && stat.stat1D.count > 8f) return true
            if (stat.stat1W.reliability > 0.45f && stat.stat1W.count > 16f) return true
            if (stat.stat1M.reliability > 0.35f && stat.stat1M.count > 32f) return true

            return false
        }

        private fun updateUptimeStat(stat: NetworkStat, good: Boolean, time: Long) {
            val age = time - lastTry
            stat.stat2H.update(good, age, 3600.0f * 2)
            stat.stat8H.update(good, age, 3600.0f * 8)
            stat.stat1D.update(good, age, 3600.0f * 24)
            stat.stat1W.update(good, age, 3600.0f * 24 * 7)
            stat.stat1M.update(good, age, 3600.0f * 24 * 30)
        }

        companion object {
            fun new(from: Address) = Entry(from, 0, 0, null)
            fun newConnected(time: Long, userAgent: String) = Entry(Network.LOOPBACK, 0, 0, NetworkStat(time, userAgent))
        }

        @Suppress("unused")
        @Serializable
        class Info(
                val address: String,
                val from: String,
                val attempts: Int,
                var lastTry: Long,
                val stat: NetworkStat?
        ) {
            constructor(entry: Entry, address: Address) : this(
                    address.toString(),
                    entry.from.toString(),
                    entry.attempts,
                    entry.lastTry,
                    entry.stat
            )
        }
    }

    @Serializable
    class UptimeStat(var weight: Float, var count: Float, var reliability: Float) {
        constructor() : this(0.0f, 0.0f, 0.0f)

        fun update(good: Boolean, age: Long, tau: Float) {
            val f: Float = exp(-age / tau)
            reliability = reliability * f + if (good) 1.0f - f else 0.0f
            count = count * f + 1.0f
            weight = weight * f + (1.0f - f)
        }
    }

    @Serializable
    internal class EntryV1(val from: AddressV1, val attempts: Int, val lastTry: Long, val lastConnected: Long)

    @Serializable
    internal class EntryV2(val from: AddressV1, val attempts: Int, val lastTry: Long, val stat: NetworkStatV1?)

    @Serializable
    internal class EntryV3(val from: Address, val attempts: Int, val lastTry: Long, val stat: NetworkStatV1?)

    @Serializable
    internal class NetworkStatV1(var lastConnected: Long, var userAgent: String, val stat2H: UptimeStat, val stat8H: UptimeStat, val stat1D: UptimeStat, val stat1W: UptimeStat, val stat1M: UptimeStat)
}
