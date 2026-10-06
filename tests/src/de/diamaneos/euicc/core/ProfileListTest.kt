// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class ProfileListTest {
    @Test
    fun parsesStatesClassesAndRules() {
        val parsed = list(
            raw(ICCID_A, state = 1, profileClass = 2, policyRules = PolicyRules.DO_NOT_DELETE),
            raw(ICCID_B, state = 0, profileClass = 0),
            raw(ICCID_C, state = 0, profileClass = 1),
        )
        assertEquals(0, parsed.skipped)
        val (a, b, c) = parsed.profiles
        assertEquals(ProfileState.ENABLED, a.state)
        assertEquals(ProfileClass.OPERATIONAL, a.profileClass)
        assertTrue(a.mayDisable)
        assertFalse(a.mayDelete)
        assertEquals(ProfileState.DISABLED, b.state)
        assertEquals(ProfileClass.TESTING, b.profileClass)
        assertEquals(ProfileClass.PROVISIONING, c.profileClass)
    }

    @Test
    fun unsetClassMeansOperational() {
        assertEquals(ProfileClass.OPERATIONAL, list(raw(profileClass = -1)).profiles.single().profileClass)
    }

    @Test
    fun skipsNullEntriesAndBadProfiles() {
        // The framework's array keeps its size when it drops profiles without an ICCID.
        val parsed = list(
            raw(ICCID_A),
            null,
            raw(iccid = null),
            raw(iccid = "89490000000000000AB"),
            raw(iccid = "8949"),
            raw(ICCID_B, state = 7),
            raw(ICCID_C, profileClass = 9),
            raw(ICCID_A, state = 1),
        )
        assertEquals(1, parsed.profiles.size)
        assertEquals(7, parsed.skipped)
        // The first of two entries with one ICCID wins.
        assertFalse(parsed.profiles.single().isEnabled)
    }

    @Test
    fun keepsTheFrameworkIndex() {
        val parsed = list(null, raw(ICCID_A), raw(iccid = null), raw(ICCID_B))
        assertEquals(listOf(1, 3), parsed.profiles.map { it.index })
    }

    @Test
    fun findsTheEnabledProfile() {
        val parsed = list(raw(ICCID_A), raw(ICCID_B, state = 1))
        assertSame(parsed.find(ICCID_B), parsed.enabled)
        assertEquals(1, parsed.enabledCount)
        assertNull(list(raw(ICCID_A)).enabled)
        assertNull(parsed.find(ICCID_C))
    }

    @Test
    fun displayNamePrefersNicknameThenNameThenProvider() {
        assertEquals("Work", list(raw(nickname = " Work ", profileName = "P", provider = "C"))
            .profiles.single().displayName)
        assertEquals("P", list(raw(nickname = " ", profileName = "P", provider = "C"))
            .profiles.single().displayName)
        assertEquals("C", list(raw(provider = "C")).profiles.single().displayName)
        assertNull(list(raw()).profiles.single().displayName)
    }

    @Test
    fun displayOrderIsEnabledThenNameThenUnnamed() {
        val parsed = list(
            raw(ICCID_A),
            raw(ICCID_B, nickname = "beta"),
            raw(ICCID_C, nickname = "Alpha", state = 1),
            raw("8949000000000000004", nickname = "alpha 2"),
        )
        assertEquals(listOf("Alpha", "alpha 2", "beta", null), parsed.forDisplay().map { it.displayName })
    }

    @Test
    fun textNeverCarriesIdentifiersOrNames() {
        val parsed = list(raw(ICCID_A, nickname = "Home", profileName = "Plan", provider = "Carrier", state = 1))
        val texts = listOf(parsed.summary(), parsed.profiles.single().toString(),
            raw(ICCID_A, nickname = "Home").toString())
        for (text in texts) {
            for (secret in listOf(ICCID_A, "Home", "Plan", "Carrier")) {
                assertFalse("$secret in $text", text.contains(secret))
            }
        }
        assertEquals(
            "profiles=1 enabled=1 skipped=0 classes=testing:0,provisioning:0,operational:1",
            parsed.summary())
    }
}
