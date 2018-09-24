/*
 * Copyright (c) 2018 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.db

import ninja.blacknet.network.Address
import ninja.blacknet.network.Node
import org.mapdb.DBMaker
import org.mapdb.Serializer
import kotlin.math.min

object PeerDB {
    const val NETWORK_TIMEOUT = 30 * 60
    private val db = DBMaker.fileDB("peer.db").transactionEnable().fileMmapEnableIfSupported().closeOnJvmShutdown().make()
    private val map = db.hashMap("peers", Serializer.ELSA, Serializer.ELSA).createOrOpen()

    fun commit() {
        db.commit()
    }

    fun size(): Int {
        return map.size
    }

    fun connected(address: Address) {
        if (address.isLocal()) return
        val entry = map[address] as Entry?
        if (entry != null)
            map[address] = Entry(entry.from, 0, 0, Node.time())
        else
            map[address] = Entry(Node.localAddress, 0, 0, Node.time())
    }

    fun failed(address: Address) {
        if (address.isLocal()) return
        val entry = map[address] as Entry?
        if (entry != null)
            map[address] = Entry(entry.from, entry.attempts + 1, Node.time(), entry.lastConnected)
        else
            map[address] = Entry(Node.localAddress, 0, Node.time(), 0)
    }

    fun getAll(): List<Address> {
        return map.keys.toList() as List<Address>
    }

    fun getCandidate(): Address? {
        return getRandom(1).firstOrNull()
    }

    fun getRandom(n: Int): MutableList<Address> {
        val x = min(size(), n)
        return getAll().shuffled().take(x).toMutableList()
    }

    fun add(peers: List<Address>, from: Address) {
        peers.forEach {
            if (!map.contains(it))
                map[it] = Entry(from, 0, 0, 0)
        }
        commit()
    }

    class Entry(val from: Address, val attempts: Int, val lastTry: Long, val lastConnected: Long) : java.io.Serializable
}