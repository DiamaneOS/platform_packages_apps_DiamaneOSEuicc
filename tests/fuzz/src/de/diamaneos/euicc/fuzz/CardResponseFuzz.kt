// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.fuzz

import de.diamaneos.euicc.core.CardResponses
import de.diamaneos.euicc.core.EuiccInfo1
import de.diamaneos.euicc.core.EuiccInfo2
import de.diamaneos.euicc.core.GsmaCi
import de.diamaneos.euicc.core.NotificationEvents
import de.diamaneos.euicc.core.PendingNotification
import de.diamaneos.euicc.core.ServerText

/**
 * What the eUICC returns through the framework: PendingNotification (ProfileInstallationResult
 * and OtherSignedNotification), the AuthenticateServer, PrepareDownload and CancelSession
 * responses, EUICCInfo1 and EUICCInfo2. Input: the response, and a 16-byte transaction ID part.
 * - parse throws only IllegalArgumentException. parseOrNull, CardResponses and
 *   EuiccInfo2.summary throw nothing.
 * - A notification has exactly one known event, and its raw bytes are the input.
 * - EUICCInfo1 key IDs are 1 to 32 bytes. The dump text for them is bounded.
 */
object CardResponseFuzz {
    @JvmStatic
    fun fuzzerTestOneInput(data: ByteArray) {
        val (response, txid) = Parts.split(data, 2)
        orIae { PendingNotification.parse(response) }?.let { n ->
            invariant(n.raw === response) { "raw bytes" }
            invariant(Integer.bitCount(n.metadata.event) == 1 && n.metadata.event and NotificationEvents.ALL == n.metadata.event) { "event" }
            n.install?.let { invariant(it.metadata === n.metadata) { "install metadata" } }
            n.metadata.iccid?.let { invariant(it.length in 18..22 && it.all(Char::isDigit)) { "ICCID" } }
            // The screen shows the address cleaned.
            ConsentChecks.problem(ServerText.clean(n.metadata.address, ServerText.MAX_ADDRESS_CHARS), ServerText.MAX_ADDRESS_CHARS)
                ?.let { throw Violation("notification address: $it") }
        }
        PendingNotification.parseOrNull(response)
        CardResponses.authenticateServerOk(response, txid)
        CardResponses.prepareDownloadOk(response, txid)
        CardResponses.cancelSessionOk(response)
        orIae { EuiccInfo1.parse(response) }?.let { info ->
            for (id in info.ciForVerification + info.ciForSigning) {
                invariant(id.size in 1..32) { "key ID size" }
                invariant(GsmaCi.describe(id).length <= 64) { "CI name" }
            }
        }
        EuiccInfo2.summary(response)?.let { s ->
            invariant(s.rspCapabilities.size <= EuiccInfo2.RSP_CAPABILITIES.size) { "capabilities" }
        }
        EuiccInfo2.firmwareVersion(response)
    }
}
