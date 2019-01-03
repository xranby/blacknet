/*
 * Copyright (c) 2018 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.db

import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import mu.KotlinLogging
import ninja.blacknet.network.Address
import ninja.blacknet.network.Node
import ninja.blacknet.util.delay
import org.mapdb.DBMaker
import org.mapdb.HTreeMap
import org.mapdb.Serializer
import kotlin.math.min
import kotlin.random.Random

private val logger = KotlinLogging.logger {}

object PeerDB {
    const val DELAY = 60 * 60
    private val db = DBMaker.fileDB("db/peers").transactionEnable().fileMmapEnable().closeOnJvmShutdown().make()
    @Suppress("UNCHECKED_CAST")
    private val map = db.hashMap("peers", Serializer.ELSA, Serializer.ELSA).createOrOpen() as HTreeMap<Address, Entry>

    init {
        GlobalScope.launch { oldEntriesRemover() }
    }

    fun commit() {
        db.commit()
    }

    fun size(): Int {
        return map.size
    }

    fun isEmpty(): Boolean {
        return map.isEmpty()
    }

    fun connected(address: Address) {
        if (address.isLocal()) return
        val entry = map[address]
        if (entry != null)
            map[address] = Entry(entry.from, 0, 0, Node.time())
        else
            map[address] = Entry(Address.LOOPBACK, 0, 0, Node.time())
    }

    fun attempt(address: Address) {
        if (address.isLocal()) return
        val entry = map[address]
        if (entry != null)
            map[address] = Entry(entry.from, entry.attempts + 1, Node.time(), entry.lastConnected)
        else
            map[address] = Entry(Address.LOOPBACK, 0, Node.time(), 0)
    }

    fun getAll(): List<Address> {
        return map.keys.toList()
    }

    fun getCandidate(filter: List<Address>): Address? {
        val candidates = map.keys.filter { !filter.contains(it) && it.isEnabled() }
        if (candidates.isEmpty())
            return null
        return candidates[Random.nextInt(candidates.size)]
    }

    fun getRandom(n: Int): MutableList<Address> {
        val x = min(size(), n)
        return map.keys.shuffled().asSequence().take(x).toMutableList()
    }

    fun add(peers: List<Address>, from: Address) {
        peers.forEach {
            add(it, from)
        }
    }

    fun add(peer: Address, from: Address): Boolean {
        if (!map.contains(peer)) {
            map[peer] = Entry(from, 0, 0, 0)
            return true
        }
        return false
    }

    private suspend fun oldEntriesRemover() {
        while (true) {
            delay(DELAY)
            if (Node.isOffline()) continue

            val toRemove = ArrayList<Address>()
            val currTime = Node.time()
            map.forEach { k, v ->
                if (v.isOld(currTime))
                    toRemove.add(k)
            }
            if (!toRemove.isEmpty()) {
                toRemove.forEach { map.remove(it) }
                commit()
                logger.info("Removed ${toRemove.size} old entries from peer db")
            }
        }
    }

    class Entry(val from: Address, val attempts: Int, val lastTry: Long, val lastConnected: Long) : java.io.Serializable {
        fun isOld(currTime: Long): Boolean {
            if (lastConnected == 0L && attempts > 15)
                return true
            if (lastConnected != 0L && currTime - lastConnected > 15 * 24 * 60 * 60)
                return true
            return false
        }
    }
}