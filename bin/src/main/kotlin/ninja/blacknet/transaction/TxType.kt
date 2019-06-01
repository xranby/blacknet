/*
 * Copyright (c) 2018 Pavel Vasin
 *
 * Licensed under the Jelurida Public License version 1.1
 * for the Blacknet Public Blockchain Platform (the "License");
 * you may not use this file except in compliance with the License.
 * See the LICENSE.txt file at the top-level directory of this distribution.
 */

package ninja.blacknet.transaction

import kotlinx.serialization.KSerializer

enum class TxType(val type: Byte) {
    Transfer(0),
    Burn(1),
    Lease(2),
    CancelLease(3),
    Bundle(4),
    CreateHTLC(5),
    UnlockHTLC(6),
    RefundHTLC(7),
    SpendHTLC(8),
    CreateMultisig(9),
    SpendMultisig(10),
    Generated(254.toByte()),
    ;

    companion object {
        fun getSerializer(type: Byte): KSerializer<out TxData>? {
            return when (type) {
                Transfer.type -> ninja.blacknet.transaction.Transfer.serializer()
                Burn.type -> ninja.blacknet.transaction.Burn.serializer()
                Lease.type -> ninja.blacknet.transaction.Lease.serializer()
                CancelLease.type -> ninja.blacknet.transaction.CancelLease.serializer()
                Bundle.type -> ninja.blacknet.transaction.Bundle.serializer()
                CreateHTLC.type -> ninja.blacknet.transaction.CreateHTLC.serializer()
                UnlockHTLC.type -> ninja.blacknet.transaction.UnlockHTLC.serializer()
                RefundHTLC.type -> ninja.blacknet.transaction.RefundHTLC.serializer()
                SpendHTLC.type -> ninja.blacknet.transaction.SpendHTLC.serializer()
                CreateMultisig.type -> ninja.blacknet.transaction.CreateMultisig.serializer()
                SpendMultisig.type -> ninja.blacknet.transaction.SpendMultisig.serializer()
                else -> null
            }
        }
    }
}
