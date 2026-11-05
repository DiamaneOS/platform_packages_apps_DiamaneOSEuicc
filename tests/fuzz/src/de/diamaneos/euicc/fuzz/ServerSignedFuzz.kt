// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.fuzz

import de.diamaneos.euicc.core.ServerSigned1
import de.diamaneos.euicc.core.SmdpSigned2

/**
 * ServerSigned1 and SmdpSigned2: what the server signs and the eUICC checks again, which this
 * app reads for the transaction ID, the challenge, the address and the confirmation code flag.
 * - Only IllegalArgumentException may come out.
 * - Accepted input has one reading: each component once, tags in allowed forms, so the eUICC
 *   cannot read another address or flag than the one this app checked.
 */
object ServerSignedFuzz {
    @JvmStatic
    fun fuzzerTestOneInput(data: ByteArray) {
        orIae { ServerSigned1.parse(data) }?.let { s ->
            invariant(s.transactionId.size in 1..16 && s.euiccChallenge.size == 16 && s.serverChallenge.size == 16) { "sizes" }
            unique(data)
        }
        orIae { SmdpSigned2.parse(data) }?.let { unique(data) }
    }

    private fun unique(data: ByteArray) {
        val top = RefDer.decode(data)
        val children = top.single().children()
        invariant((top + children).none { it.badTag }) { "tag in a forbidden form accepted" }
        invariant(children.map(RefDer::key).toSet().size == children.size) { "duplicate component accepted" }
    }
}
