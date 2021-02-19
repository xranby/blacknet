/*
 * Copyright (c) 2019-2020 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.logging

import ninja.blacknet.dataDir
import java.io.File
import java.util.logging.FileHandler
import java.util.logging.SimpleFormatter

class FileHandler : FileHandler(
        File(dataDir, "debug.log").getPath(),
        5000000,
        2,
        true
) {
    init {
        setFormatter(SimpleFormatter())
    }
}
