/*
 * Copyright (c) 2019 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.util

import ninja.blacknet.Config
import java.util.logging.FileHandler
import java.util.logging.SimpleFormatter

class FileHandler : FileHandler(Config.dataDir + "/debug.log", 10000000, 1,true) {
    init {
        setFormatter(SimpleFormatter())
    }
}
