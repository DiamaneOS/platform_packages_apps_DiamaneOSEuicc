// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.core

/** What a switch request needs on the card. */
sealed interface SwitchPlan {
    /** The target is already enabled, or nothing is enabled to disable. */
    data object NoOp : SwitchPlan

    /** Another profile is enabled and the caller did not allow turning it off. */
    data object MustDeactivate : SwitchPlan

    /** Enable [profile]. The card disables the enabled one itself. */
    class Enable(val profile: Profile) : SwitchPlan

    /** Disable [profile] and enable nothing. */
    class Disable(val profile: Profile) : SwitchPlan

    /** Not allowed. [result] is the EuiccService result. */
    class Refused(val result: Int) : SwitchPlan
}

/** What a delete request needs on the card. */
sealed interface DeletePlan {
    class Delete(val profile: Profile) : DeletePlan

    /** The profile is enabled: disable it first, as EuiccService requires. */
    class DisableThenDelete(val profile: Profile) : DeletePlan

    class Refused(val result: Int) : DeletePlan
}

/**
 * What the user agreed to in the screen's turn-on dialog: turning off the profile that was
 * enabled then, and its deletion if [deletesCurrent].
 */
class SwitchConsent private constructor(private val currentIccid: String?, val deletesCurrent: Boolean) {
    /** Whether the user agreed to what turning off [current] does now. */
    fun covers(current: Profile): Boolean =
        current.iccid == currentIccid && (deletesCurrent || !current.deletedWhenDisabled)

    companion object {
        fun of(current: Profile?) = SwitchConsent(current?.iccid, current?.deletedWhenDisabled == true)
    }
}

/** Decides profile changes from the card's current list. No card access. */
object Planner {
    /**
     * [targetIccid] null means: disable the enabled profile and enable none. [forceDeactivate]
     * is the framework's forceDeactivateSim: without it, turning off another enabled profile
     * needs the user's consent first (RESULT_MUST_DEACTIVATE_SIM).
     */
    fun switch(list: ProfileList, targetIccid: String?, forceDeactivate: Boolean): SwitchPlan {
        val current = list.enabled
        if (targetIccid == null) {
            return when {
                current == null -> SwitchPlan.NoOp
                !current.mayDisable -> refusedSwitch(Results.DETAIL_POLICY_RULES)
                else -> SwitchPlan.Disable(current)
            }
        }
        val target = list.find(targetIccid) ?: return refusedSwitch(Results.DETAIL_PROFILE_NOT_FOUND)
        if (target.isEnabled) return SwitchPlan.NoOp
        if (current != null) {
            if (!current.mayDisable) return refusedSwitch(Results.DETAIL_POLICY_RULES)
            if (!forceDeactivate) return SwitchPlan.MustDeactivate
        }
        return SwitchPlan.Enable(target)
    }

    /**
     * The screen's turn on, planned on the list read just before the card command. If the enabled
     * profile changed since the dialog, or would now be deleted without the user being told, the
     * plan is MustDeactivate and the screen asks again.
     */
    fun switch(list: ProfileList, targetIccid: String, consent: SwitchConsent): SwitchPlan {
        val current = list.enabled
        return switch(list, targetIccid, forceDeactivate = current == null || consent.covers(current))
    }

    /** Turn off one profile, if it is still the enabled one (the screen's "Turn off"). */
    fun disable(list: ProfileList, iccid: String): SwitchPlan {
        val profile = list.find(iccid) ?: return refusedSwitch(Results.DETAIL_PROFILE_NOT_FOUND)
        return when {
            !profile.isEnabled -> SwitchPlan.NoOp
            !profile.mayDisable -> refusedSwitch(Results.DETAIL_POLICY_RULES)
            else -> SwitchPlan.Disable(profile)
        }
    }

    fun delete(list: ProfileList, iccid: String): DeletePlan {
        val profile = list.find(iccid) ?: return refusedDelete(Results.DETAIL_PROFILE_NOT_FOUND)
        return when {
            !profile.mayDelete -> refusedDelete(Results.DETAIL_POLICY_RULES)
            !profile.isEnabled -> DeletePlan.Delete(profile)
            !profile.mayDisable -> refusedDelete(Results.DETAIL_POLICY_RULES)
            else -> DeletePlan.DisableThenDelete(profile)
        }
    }

    private fun refusedSwitch(detail: Int) =
        SwitchPlan.Refused(Results.error(Results.OPERATION_SWITCH, detail))

    private fun refusedDelete(detail: Int) =
        DeletePlan.Refused(Results.error(Results.OPERATION_EUICC_CARD, detail))
}
