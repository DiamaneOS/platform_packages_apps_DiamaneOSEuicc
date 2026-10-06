// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.card

import android.content.Context
import android.service.euicc.EuiccProfileInfo
import android.telephony.TelephonyManager
import android.telephony.UiccSlotInfo
import android.telephony.euicc.EuiccCardManager
import android.util.Log
import de.diamaneos.euicc.core.ProfileList
import de.diamaneos.euicc.core.RawProfile
import de.diamaneos.euicc.core.Results
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/** An eUICC: its physical slot and its card ID (the EID). [toString] leaves out the EID. */
class Euicc(val slot: Int, val cardId: String, val removable: Boolean) {
    override fun toString() = "Euicc(slot=$slot, removable=$removable)"
}

/** An EuiccCardManager result code, and the value the call returned (null for Void calls). */
class CardResult<T>(val code: Int, val value: T?) {
    val ok: Boolean get() = code == Results.CARD_OK
}

/** The profile list with the framework's own objects, which the service hands back. */
class Profiles(val infos: List<EuiccProfileInfo?>, val list: ProfileList)

/**
 * Blocking access to the eUICC through the framework: TelephonyManager for the slots,
 * EuiccCardManager (EuiccCardController in the phone process) for the card commands. The phone
 * process accepts card commands only from the active LPA package. Call from worker threads.
 * Nothing here logs an identifier.
 */
class CardClient(context: Context) {
    private val telephony = context.getSystemService(TelephonyManager::class.java)
    private val cards = context.getSystemService(EuiccCardManager::class.java)

    /** The eUICC in a physical slot, or null if the slot has none or the card is not present. */
    fun euicc(slot: Int): Euicc? = slots()?.getOrNull(slot)?.let { toEuicc(slot, it) }

    /** The eUICC the screen manages: the first built-in one, else the first one. */
    fun defaultEuicc(): Euicc? {
        val all = slots()?.mapIndexedNotNull { slot, info -> info?.let { toEuicc(slot, it) } }
            ?: return null
        return all.firstOrNull { !it.removable } ?: all.firstOrNull()
    }

    fun profiles(euicc: Euicc): CardResult<Profiles> {
        val result = call<Array<EuiccProfileInfo?>>(READ_TIMEOUT_S) { m, cb ->
            m.requestAllProfiles(euicc.cardId, DIRECT, cb)
        }
        if (!result.ok) return CardResult(result.code, null)
        val infos = result.value?.toList().orEmpty()
        return CardResult(result.code, Profiles(infos, ProfileList.parse(infos.map { it?.toRaw() })))
    }

    fun euiccInfo2(euicc: Euicc): CardResult<ByteArray> =
        call(READ_TIMEOUT_S) { m, cb -> m.requestEuiccInfo2(euicc.cardId, DIRECT, cb) }

    /** Enables a profile on a port; the card disables the enabled one and restarts. */
    fun enable(euicc: Euicc, iccid: String, port: Int): Int =
        call<EuiccProfileInfo>(WRITE_TIMEOUT_S) { m, cb ->
            m.switchToProfile(euicc.cardId, iccid, port, true /* refresh */, DIRECT, cb)
        }.code

    /** Disables an enabled profile; the card restarts. */
    fun disable(euicc: Euicc, iccid: String): Int =
        call<Void>(WRITE_TIMEOUT_S) { m, cb ->
            m.disableProfile(euicc.cardId, iccid, true /* refresh */, DIRECT, cb)
        }.code

    fun delete(euicc: Euicc, iccid: String): Int =
        call<Void>(WRITE_TIMEOUT_S) { m, cb -> m.deleteProfile(euicc.cardId, iccid, DIRECT, cb) }.code

    fun setNickname(euicc: Euicc, iccid: String, nickname: String): Int =
        call<Void>(WRITE_TIMEOUT_S) { m, cb ->
            m.setNickname(euicc.cardId, iccid, nickname, DIRECT, cb)
        }.code

    /** ES10c eUICCMemoryReset with EuiccCardManager.RESET_OPTION_* [options]. */
    fun resetMemory(euicc: Euicc, options: Int): Int =
        call<Void>(WRITE_TIMEOUT_S) { m, cb -> m.resetMemory(euicc.cardId, options, DIRECT, cb) }.code

    private fun slots(): Array<UiccSlotInfo?>? = try {
        telephony?.uiccSlotsInfo
    } catch (e: RuntimeException) {
        Log.w(TAG, "slot info unavailable: ${e.javaClass.simpleName}")
        null
    }

    private fun toEuicc(slot: Int, info: UiccSlotInfo): Euicc? {
        if (!info.getIsEuicc()) return null
        if (info.getCardStateInfo() != UiccSlotInfo.CARD_STATE_INFO_PRESENT) return null
        val cardId = info.getCardId()
        if (cardId.isNullOrEmpty()) return null
        return Euicc(slot, cardId, info.isRemovable())
    }

    /**
     * Runs one EuiccCardManager call and waits for its callback. A missing manager, an
     * exception (no eUICC feature, a security exception) or no answer within the timeout give
     * an error code; a callback after the timeout is dropped.
     */
    private fun <T> call(
        timeoutS: Long,
        request: (EuiccCardManager, EuiccCardManager.ResultCallback<T>) -> Unit,
    ): CardResult<T> {
        val manager = cards ?: return CardResult(Results.CARD_EUICC_NOT_FOUND, null)
        val done = CountDownLatch(1)
        val result = AtomicReference<CardResult<T>>()
        try {
            request(manager, EuiccCardManager.ResultCallback<T> { code, value ->
                result.set(CardResult(code, value))
                done.countDown()
            })
        } catch (e: RuntimeException) {
            Log.w(TAG, "card call failed: ${e.javaClass.simpleName}")
            return CardResult(Results.CARD_UNKNOWN_ERROR, null)
        }
        val answered = try {
            done.await(timeoutS, TimeUnit.SECONDS)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            false
        }
        return if (answered) result.get() else CardResult(Results.CARD_TIMEOUT, null)
    }

    private companion object {
        const val TAG = "DiamaneOSEuicc"
        const val READ_TIMEOUT_S = 20L

        /** Enabling and disabling restart the card. */
        const val WRITE_TIMEOUT_S = 60L
        val DIRECT = Executor { it.run() }

        fun EuiccProfileInfo.toRaw() = RawProfile(
            iccid = iccid,
            nickname = nickname,
            profileName = profileName,
            serviceProviderName = serviceProviderName,
            state = state,
            profileClass = profileClass,
            policyRules = policyRules,
        )
    }
}
