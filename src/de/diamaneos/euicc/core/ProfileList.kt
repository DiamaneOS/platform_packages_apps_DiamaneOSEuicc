// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.core

/**
 * The profiles on one eUICC, in the card's order.
 *
 * Only one profile is enabled at a time: the FP6's eUICC has one port and no multiple enabled
 * profiles (MEP), and the framework reports it that way.
 */
class ProfileList(val profiles: List<Profile>, val skipped: Int) {
    val enabled: Profile? get() = profiles.firstOrNull { it.isEnabled }
    val enabledCount: Int get() = profiles.count { it.isEnabled }

    fun find(iccid: String): Profile? = profiles.firstOrNull { it.iccid == iccid }

    /** Enabled first, then by name; profiles without a name last. */
    fun forDisplay(): List<Profile> = profiles.sortedWith(
        compareByDescending<Profile> { it.isEnabled }
            .thenBy { it.displayName == null }
            .thenBy(String.CASE_INSENSITIVE_ORDER) { it.displayName ?: "" })

    /** Counts only, for logs and dumps. */
    fun summary(): String =
        "profiles=${profiles.size} enabled=$enabledCount skipped=$skipped " +
            "classes=" + ProfileClass.entries.joinToString(",") { c ->
                "${c.name.lowercase()}:${profiles.count { it.profileClass == c }}"
            }

    companion object {
        // EuiccProfileInfo values.
        private const val STATE_DISABLED = 0
        private const val STATE_ENABLED = 1
        private const val CLASS_UNSET = -1
        private const val CLASS_TESTING = 0
        private const val CLASS_PROVISIONING = 1
        private const val CLASS_OPERATIONAL = 2

        /** ITU-T E.118 ICCIDs, as the framework gives them (BCD, trailing F removed). */
        private val ICCID = Regex("[0-9]{18,22}")

        /**
         * Builds the list from the framework's answer. The framework's array can hold null
         * entries (it skips profiles without an ICCID but keeps the array size). Entries without
         * a valid ICCID, with an unknown state or a repeated ICCID are skipped and counted.
         * A missing class means operational (the SGP.22 default).
         */
        fun parse(raw: List<RawProfile?>): ProfileList {
            val profiles = ArrayList<Profile>(raw.size)
            val seen = HashSet<String>()
            var skipped = 0
            raw.forEachIndexed { index, r ->
                val iccid = r?.iccid
                val state = when (r?.state) {
                    STATE_ENABLED -> ProfileState.ENABLED
                    STATE_DISABLED -> ProfileState.DISABLED
                    else -> null
                }
                val profileClass = when (r?.profileClass) {
                    CLASS_TESTING -> ProfileClass.TESTING
                    CLASS_PROVISIONING -> ProfileClass.PROVISIONING
                    CLASS_OPERATIONAL, CLASS_UNSET -> ProfileClass.OPERATIONAL
                    else -> null
                }
                if (r == null || iccid == null || !ICCID.matches(iccid) || state == null ||
                    profileClass == null || !seen.add(iccid)) {
                    skipped++
                    return@forEachIndexed
                }
                profiles += Profile(
                    index = index,
                    iccid = iccid,
                    nickname = r.nickname,
                    profileName = r.profileName,
                    providerName = r.serviceProviderName,
                    state = state,
                    profileClass = profileClass,
                    policyRules = r.policyRules,
                )
            }
            return ProfileList(profiles, skipped)
        }
    }
}
