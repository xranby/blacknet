/*
 * Copyright (c) 2019-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.db

import mu.KotlinLogging
import ninja.blacknet.Config
import ninja.blacknet.Runtime
import ninja.blacknet.dataDir
import org.iq80.leveldb.*
import java.io.File

private val logger = KotlinLogging.logger {}

object LevelDB {
    private val factory: DBFactory = loadFactory()
    private val db: DB = factory.open(File(dataDir, "leveldb"), options())

    internal fun iterator(): DBIterator {
        return db.iterator()
    }

    internal fun seek(iterator: DBIterator, dbKey: DBKey): Boolean {
        iterator.seek(byteArrayOf(dbKey.prefix))
        return if (iterator.hasNext())
            dbKey % iterator.peekNext()
        else
            false
    }

    fun getProperty(name: String): String? {
        return db.getProperty(name)
    }

    fun get(dbKey: DBKey): ByteArray? {
        return db.get(+dbKey)
    }

    fun get(dbKey: DBKey, key: ByteArray): ByteArray? {
        return db.get(dbKey + key)
    }

    internal fun get(unkey: ByteArray): ByteArray? {
        return db.get(unkey)
    }

    fun contains(dbKey: DBKey, key: ByteArray): Boolean {
        return get(dbKey, key) != null
    }

    fun put(dbKey: DBKey, key: ByteArray, bytes: ByteArray) {
        db.put(dbKey + key, bytes)
    }

    fun delete(dbKey: DBKey, key: ByteArray) {
        db.delete(dbKey + key)
    }

    fun createWriteBatch(): WriteBatch {
        return WriteBatch(db.createWriteBatch())
    }

    class WriteBatch internal constructor(private val batch: org.iq80.leveldb.WriteBatch) {
        fun put(dbKey: DBKey, bytes: ByteArray) {
            batch.put(+dbKey, bytes)
        }

        fun put(dbKey: DBKey, key: ByteArray, bytes: ByteArray) {
            batch.put(dbKey + key, bytes)
        }

        fun delete(dbKey: DBKey) {
            batch.delete(+dbKey)
        }

        fun delete(dbKey: DBKey, key: ByteArray) {
            batch.delete(dbKey + key)
        }

        internal fun delete(unkey: ByteArray) {
            batch.delete(unkey)
        }

        fun write(sync: Boolean = false) {
            db.write(batch, if (sync) syncOptions else writeOptions)
            batch.close()
        }

        fun close() {
            batch.close()
        }
    }

    private fun options(): Options {
        val cacheSize = Config.instance.dbcache.bytes
        val options = Options()
                .createIfMissing(true)
                .paranoidChecks(true)
                .compressionType(CompressionType.NONE)
                .cacheSize(cacheSize / 2L)
                .writeBufferSize(cacheSize / 4)
                .xMaxOpenFiles()
                .logger(DBLogger)
        logger.info("LevelDB cache ${Config.instance.dbcache.hrp(false)}, max open files ${options.maxOpenFiles()}")
        return options
    }

    private fun Options.xMaxOpenFiles(): Options {
        return if (Runtime.macOS || !System.getProperty("os.arch").contains("64"))
            maxOpenFiles(64)
        else
            this
    }

    private fun loadFactory(): DBFactory {
        for ((name, clazz) in arrayOf(
                Pair("LevelDB JNI", "org.fusesource.leveldbjni.JniDBFactory"),
                Pair("LevelDB Java", "org.iq80.leveldb.impl.Iq80DBFactory"))) {
            for (loader in arrayOf(ClassLoader.getSystemClassLoader(), javaClass.classLoader)) {
                try {
                    val factory = loader.loadClass(clazz).getConstructor().newInstance() as DBFactory
                    logger.info("Loaded $name")
                    return factory
                } catch (e: Throwable) {
                }
            }
        }
        throw RuntimeException("Can't load LevelDB")
    }

    private object DBLogger : Logger {
        override fun log(message: String) = logger.debug { "LevelDB: $message" }
    }

    private val writeOptions = WriteOptions()
    private val syncOptions = WriteOptions().sync(true)
}
