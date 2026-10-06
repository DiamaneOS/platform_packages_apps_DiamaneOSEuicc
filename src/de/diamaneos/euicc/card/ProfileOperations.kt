// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.card

import android.util.Log
import de.diamaneos.euicc.core.DeletePlan
import de.diamaneos.euicc.core.Nickname
import de.diamaneos.euicc.core.Planner
import de.diamaneos.euicc.core.ProfileList
import de.diamaneos.euicc.core.Results
import de.diamaneos.euicc.core.SwitchPlan

/**
 * Profile changes, shared by the EuiccService and the screen. Each reads the card's current
 * list, plans the change, then runs it; one change at a time in this process. Returns
 * EuiccService result codes. Logs result codes only.
 */
class ProfileOperations(private val client: CardClient) {

    fun switch(euicc: Euicc, port: Int, iccid: String?, forceDeactivate: Boolean): Int =
        withList(euicc, "switch") { list ->
            run(euicc, port, Planner.switch(list, iccid, forceDeactivate))
        }

    /** Turns off [iccid] if it is still the enabled profile. */
    fun disable(euicc: Euicc, iccid: String): Int = withList(euicc, "disable") { list ->
        run(euicc, 0, Planner.disable(list, iccid))
    }

    fun delete(euicc: Euicc, iccid: String): Int = withList(euicc, "delete") { list ->
        when (val plan = Planner.delete(list, iccid)) {
            is DeletePlan.Refused -> plan.result
            is DeletePlan.Delete -> Results.fromCard(client.delete(euicc, plan.profile.iccid))
            is DeletePlan.DisableThenDelete -> {
                val disabled = client.disable(euicc, plan.profile.iccid)
                if (disabled != Results.CARD_OK) {
                    Results.fromCard(disabled)
                } else {
                    Results.fromCard(deleteAfterRestart(euicc, plan.profile.iccid))
                }
            }
        }
    }

    fun rename(euicc: Euicc, iccid: String, nickname: String?): Int {
        val value = Nickname.normalise(nickname) ?: return Results.INVALID_NICKNAME
        return withList(euicc, "rename") { list ->
            if (list.find(iccid) == null) {
                Results.error(Results.OPERATION_EUICC_CARD, Results.DETAIL_PROFILE_NOT_FOUND)
            } else {
                Results.fromCard(client.setNickname(euicc, iccid, value))
            }
        }
    }

    /** ES10c eUICCMemoryReset; [options] are EuiccCardManager.RESET_OPTION_* bits. */
    fun erase(euicc: Euicc, options: Int): Int = synchronized(LOCK) {
        val result = Results.fromCard(client.resetMemory(euicc, options))
        Log.i(TAG, "erase: options=$options result=$result")
        result
    }

    private fun run(euicc: Euicc, port: Int, plan: SwitchPlan): Int = when (plan) {
        SwitchPlan.NoOp -> Results.OK
        SwitchPlan.MustDeactivate -> Results.MUST_DEACTIVATE_SIM
        is SwitchPlan.Refused -> plan.result
        is SwitchPlan.Enable -> Results.fromCard(client.enable(euicc, plan.profile.iccid, port))
        is SwitchPlan.Disable -> Results.fromCard(client.disable(euicc, plan.profile.iccid))
    }

    /** Reads the list, then runs [change] on it, under the lock. Logs the result code only. */
    private inline fun withList(euicc: Euicc, what: String, change: (ProfileList) -> Int): Int =
        synchronized(LOCK) {
            val loaded = client.profiles(euicc)
            val list = loaded.value?.list
            val result = if (list == null) {
                Log.w(TAG, "$what: profile list failed, card result ${loaded.code}")
                Results.fromCard(if (loaded.ok) Results.CARD_UNKNOWN_ERROR else loaded.code)
            } else {
                change(list)
            }
            Log.i(TAG, "$what: result=$result")
            result
        }

    /**
     * The card restarts after a disable. Wait until the slot shows the same eUICC again before
     * each delete attempt (EuiccCardController logs the card ID when the card is missing), and
     * retry while the card is not back.
     */
    private fun deleteAfterRestart(euicc: Euicc, iccid: String): Int {
        var code = Results.CARD_TIMEOUT
        for (attempt in 1..DELETE_ATTEMPTS) {
            if (client.euicc(euicc.slot)?.cardId == euicc.cardId) {
                code = client.delete(euicc, iccid)
                if (!Results.isTransient(code)) break
            }
            if (attempt < DELETE_ATTEMPTS) Thread.sleep(DELETE_RETRY_MS)
        }
        return code
    }

    private companion object {
        const val TAG = "DiamaneOSEuicc"
        const val DELETE_ATTEMPTS = 10
        const val DELETE_RETRY_MS = 1500L

        /** Shared by every instance: the service and the screen run in one process. */
        val LOCK = Any()
    }
}
