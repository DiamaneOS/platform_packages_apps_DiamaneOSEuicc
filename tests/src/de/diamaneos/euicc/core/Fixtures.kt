// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.core

// Made-up identifiers in the ICCID format; no real card.
const val ICCID_A = "8949000000000000001"
const val ICCID_B = "8949000000000000002"
const val ICCID_C = "8949000000000000003"

fun raw(
    iccid: String? = ICCID_A,
    nickname: String? = null,
    profileName: String? = null,
    provider: String? = null,
    state: Int = 0,
    profileClass: Int = 2,
    policyRules: Int = 0,
) = RawProfile(iccid, nickname, profileName, provider, state, profileClass, policyRules)

fun list(vararg profiles: RawProfile?) = ProfileList.parse(profiles.toList())
