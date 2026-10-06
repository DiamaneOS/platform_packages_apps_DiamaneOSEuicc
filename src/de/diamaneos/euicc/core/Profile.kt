// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.core

/** SGP.22 ProfileState. */
enum class ProfileState { DISABLED, ENABLED }

/** SGP.22 ProfileClass. */
enum class ProfileClass { TESTING, PROVISIONING, OPERATIONAL }

/** SGP.22 profile policy rules, with the values of EuiccProfileInfo.POLICY_RULE_*. */
object PolicyRules {
    /** PPR1: the profile may not be disabled. */
    const val DO_NOT_DISABLE = 1

    /** PPR2: the profile may not be deleted. */
    const val DO_NOT_DELETE = 2

    /** The profile is deleted when it is disabled. */
    const val DELETE_AFTER_DISABLING = 4
}

/**
 * One profile on the eUICC.
 *
 * [index] is the profile's position in the list the framework returned, so the service can hand
 * the framework's own objects back. [toString] leaves out the ICCID and the names: a profile never
 * reaches a log by accident.
 */
class Profile(
    val index: Int,
    val iccid: String,
    val nickname: String?,
    val profileName: String?,
    val providerName: String?,
    val state: ProfileState,
    val profileClass: ProfileClass,
    val policyRules: Int,
) {
    val isEnabled: Boolean get() = state == ProfileState.ENABLED
    val mayDisable: Boolean get() = policyRules and PolicyRules.DO_NOT_DISABLE == 0
    val mayDelete: Boolean get() = policyRules and PolicyRules.DO_NOT_DELETE == 0
    val deletedWhenDisabled: Boolean
        get() = policyRules and PolicyRules.DELETE_AFTER_DISABLING != 0

    /** The nickname, else the profile name, else the provider; null if none is set. */
    val displayName: String?
        get() = listOf(nickname, profileName, providerName)
            .firstOrNull { !it.isNullOrBlank() }?.trim()

    override fun toString() = "Profile(state=$state, class=$profileClass, rules=$policyRules)"
}

/** A profile as the framework delivers it (EuiccProfileInfo), in plain values. */
class RawProfile(
    val iccid: String?,
    val nickname: String?,
    val profileName: String?,
    val serviceProviderName: String?,
    val state: Int,
    val profileClass: Int,
    val policyRules: Int,
) {
    override fun toString() = "RawProfile(state=$state, class=$profileClass)"
}
