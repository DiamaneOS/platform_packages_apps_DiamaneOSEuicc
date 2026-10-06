// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class PlannerTest {
    private val switchNotFound = Results.error(Results.OPERATION_SWITCH, Results.DETAIL_PROFILE_NOT_FOUND)
    private val switchPolicy = Results.error(Results.OPERATION_SWITCH, Results.DETAIL_POLICY_RULES)
    private val deleteNotFound = Results.error(Results.OPERATION_EUICC_CARD, Results.DETAIL_PROFILE_NOT_FOUND)
    private val deletePolicy = Results.error(Results.OPERATION_EUICC_CARD, Results.DETAIL_POLICY_RULES)

    @Test
    fun enablesWhenNothingIsEnabled() {
        val profiles = list(raw(ICCID_A), raw(ICCID_B))
        val plan = Planner.switch(profiles, ICCID_B, forceDeactivate = false)
        assertSame(profiles.find(ICCID_B), (plan as SwitchPlan.Enable).profile)
    }

    @Test
    fun switchingAwayNeedsConsentUnlessForced() {
        val profiles = list(raw(ICCID_A, state = 1), raw(ICCID_B))
        assertSame(SwitchPlan.MustDeactivate, Planner.switch(profiles, ICCID_B, forceDeactivate = false))
        val plan = Planner.switch(profiles, ICCID_B, forceDeactivate = true)
        assertSame(profiles.find(ICCID_B), (plan as SwitchPlan.Enable).profile)
    }

    @Test
    fun alreadyEnabledIsNoOp() {
        val profiles = list(raw(ICCID_A, state = 1))
        assertSame(SwitchPlan.NoOp, Planner.switch(profiles, ICCID_A, forceDeactivate = false))
    }

    @Test
    fun unknownTargetIsRefused() {
        val plan = Planner.switch(list(raw(ICCID_A)), ICCID_C, forceDeactivate = true)
        assertEquals(switchNotFound, (plan as SwitchPlan.Refused).result)
    }

    @Test
    fun ruleOneKeepsTheEnabledProfileOn() {
        val profiles = list(raw(ICCID_A, state = 1, policyRules = PolicyRules.DO_NOT_DISABLE), raw(ICCID_B))
        assertEquals(switchPolicy, (Planner.switch(profiles, ICCID_B, true) as SwitchPlan.Refused).result)
        assertEquals(switchPolicy, (Planner.switch(profiles, null, true) as SwitchPlan.Refused).result)
        assertEquals(switchPolicy, (Planner.disable(profiles, ICCID_A) as SwitchPlan.Refused).result)
    }

    @Test
    fun nullTargetDisablesTheEnabledProfile() {
        assertSame(SwitchPlan.NoOp, Planner.switch(list(raw(ICCID_A)), null, forceDeactivate = false))
        val profiles = list(raw(ICCID_A), raw(ICCID_B, state = 1))
        val plan = Planner.switch(profiles, null, forceDeactivate = false)
        assertSame(profiles.find(ICCID_B), (plan as SwitchPlan.Disable).profile)
    }

    @Test
    fun disableTurnsOffOnlyThatProfile() {
        val profiles = list(raw(ICCID_A, state = 1), raw(ICCID_B))
        assertSame(profiles.find(ICCID_A), (Planner.disable(profiles, ICCID_A) as SwitchPlan.Disable).profile)
        assertSame(SwitchPlan.NoOp, Planner.disable(profiles, ICCID_B))
        assertEquals(switchNotFound, (Planner.disable(profiles, ICCID_C) as SwitchPlan.Refused).result)
    }

    @Test
    fun deleteDisablesAnEnabledProfileFirst() {
        val profiles = list(raw(ICCID_A, state = 1), raw(ICCID_B))
        assertSame(profiles.find(ICCID_B), (Planner.delete(profiles, ICCID_B) as DeletePlan.Delete).profile)
        assertSame(profiles.find(ICCID_A),
            (Planner.delete(profiles, ICCID_A) as DeletePlan.DisableThenDelete).profile)
    }

    @Test
    fun deleteFollowsTheRules() {
        val profiles = list(
            raw(ICCID_A, policyRules = PolicyRules.DO_NOT_DELETE),
            raw(ICCID_B, state = 1, policyRules = PolicyRules.DO_NOT_DISABLE),
        )
        assertEquals(deletePolicy, (Planner.delete(profiles, ICCID_A) as DeletePlan.Refused).result)
        assertEquals(deletePolicy, (Planner.delete(profiles, ICCID_B) as DeletePlan.Refused).result)
        assertEquals(deleteNotFound, (Planner.delete(profiles, ICCID_C) as DeletePlan.Refused).result)
    }

    @Test
    fun refusalsAreUserResults() {
        // EuiccService reserves zero and negative values; errors must be RESULT_FIRST_USER or more.
        for (code in listOf(switchNotFound, switchPolicy, deleteNotFound, deletePolicy)) {
            assertTrue(code >= 1)
        }
    }
}
