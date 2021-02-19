/*
 * Copyright (c) 2019-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.util

import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.nio.file.Files
import java.nio.file.StandardCopyOption.ATOMIC_MOVE

fun InputStream.buffered(bufferSize: Int = DEFAULT_BUFFER_SIZE): BufferedInputStream = BufferedInputStream(this, bufferSize)
fun InputStream.data(): DataInputStream = DataInputStream(this)

fun OutputStream.buffered(bufferSize: Int = DEFAULT_BUFFER_SIZE): BufferedOutputStream = BufferedOutputStream(this, bufferSize)
fun OutputStream.data(): DataOutputStream = DataOutputStream(this)

fun moveFile(source: File, destination: File) = Files.move(source.toPath(), destination.toPath(), ATOMIC_MOVE)

inline fun FileOutputStream.sync(action: FileOutputStream.() -> Unit): Unit = use {
    action().also {
        flush()
        fd.sync()
    }
}
