// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.card

import android.service.carrier.CarrierIdentifier
import android.telephony.euicc.EuiccRulesAuthTable
import de.diamaneos.euicc.core.CardException
import de.diamaneos.euicc.core.Es9
import de.diamaneos.euicc.core.Hex
import de.diamaneos.euicc.core.OperatorId
import de.diamaneos.euicc.core.PprCheck
import de.diamaneos.euicc.core.ProfileClass
import de.diamaneos.euicc.core.Results
import de.diamaneos.euicc.core.RspCard

/**
 * The RSP card commands on one eUICC, through EuiccCardManager. A failed call throws
 * [CardException] with the framework's result code; nothing is logged here.
 */
class RspCardAdapter(private val client: CardClient, private val euicc: Euicc) : RspCard {

    override fun euiccInfo1(): ByteArray = value(client.euiccInfo1(euicc))

    override fun euiccChallenge(): ByteArray = value(client.euiccChallenge(euicc))

    override fun authenticateServer(matchingId: String, auth: Es9.InitiateAuthentication): ByteArray =
        value(client.authenticateServer(euicc, matchingId, auth.serverSigned1, auth.serverSignature1,
            auth.euiccCiPkIdToBeUsed, auth.serverCertificate))

    override fun prepareDownload(hashCc: ByteArray?, client: Es9.AuthenticateClient): ByteArray =
        value(this.client.prepareDownload(euicc, hashCc, client.smdpSigned2, client.smdpSignature2,
            client.smdpCertificate))

    override fun loadBoundProfilePackage(bpp: ByteArray): ByteArray = value(client.loadBoundProfilePackage(euicc, bpp))

    override fun cancelSession(transactionId: ByteArray, reason: Int): ByteArray =
        value(client.cancelSession(euicc, transactionId, reason))

    override fun notifications(events: Int): List<ByteArray> =
        value(client.retrieveNotifications(euicc, events)).mapNotNull { it?.data }

    override fun removeNotification(seq: Int) {
        val code = client.removeNotification(euicc, seq)
        if (code != Results.CARD_OK) throw CardException(code)
    }

    override fun hasOperationalProfile(): Boolean {
        val result = client.profiles(euicc)
        val list = result.value?.list ?: throw CardException(result.code)
        return list.profiles.any { it.profileClass == ProfileClass.OPERATIONAL }
    }

    /**
     * SGP.22 2.9.2.3: each rule must be allowed for the Profile Owner by some RAT entry. A
     * profile without an owner cannot match any entry.
     */
    override fun pprCheck(rules: Int, owner: OperatorId?): PprCheck {
        if (owner == null) return PprCheck.FORBIDDEN
        val table = value(client.rulesAuthTable(euicc))
        val carrier = CarrierIdentifier(owner.mccMnc, owner.gid1?.let(::hexUpper), owner.gid2?.let(::hexUpper))
        var consent = false
        for (rule in intArrayOf(1, 2)) { // EuiccProfileInfo.POLICY_RULE_DO_NOT_DISABLE, _DO_NOT_DELETE
            if (rules and rule == 0) continue
            val index = table.findIndex(rule, carrier)
            if (index < 0) return PprCheck.FORBIDDEN
            if (table.hasPolicyRuleFlag(index, EuiccRulesAuthTable.POLICY_RULE_FLAG_CONSENT_REQUIRED)) consent = true
        }
        return if (consent) PprCheck.CONSENT_REQUIRED else PprCheck.ALLOWED
    }

    /** EuiccPort builds the RAT's carrier GIDs as uppercase hex (IccUtils.bytesToHexString). */
    private fun hexUpper(bytes: ByteArray) = Hex.encode(bytes).uppercase(java.util.Locale.ROOT)

    private fun <T> value(result: CardResult<T>): T {
        val value = result.value
        if (!result.ok || value == null) throw CardException(if (result.ok) Results.CARD_UNKNOWN_ERROR else result.code)
        return value
    }
}
