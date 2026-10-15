// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ResultsTest {
    private fun operation(code: Int) = code ushr 24
    private fun detail(code: Int) = code and 0xFFFFFF

    @Test
    fun okStaysOk() = assertEquals(Results.OK, Results.fromCard(Results.CARD_OK))

    @Test
    fun cardErrorCodesBecomeGsmaErrors() {
        // SGP.22 EnableProfile: 2 = profileNotInDisabledState.
        val code = Results.fromCard(2)
        assertEquals(Results.OPERATION_EUICC_GSMA, operation(code))
        assertEquals(2, detail(code))
    }

    @Test
    fun frameworkErrorsMapToOperationAndDetail() {
        fun check(card: Int, op: Int, det: Int) {
            val code = Results.fromCard(card)
            assertEquals(op, operation(code))
            assertEquals(det, detail(code))
            assertTrue(code >= 1)
        }
        check(Results.CARD_EUICC_NOT_FOUND, Results.OPERATION_SYSTEM, Results.ERROR_EUICC_MISSING)
        check(Results.CARD_CALLER_NOT_ALLOWED, Results.OPERATION_SYSTEM, Results.DETAIL_CALLER_NOT_ALLOWED)
        check(Results.CARD_PROFILE_DOES_NOT_EXIST, Results.OPERATION_EUICC_CARD, Results.DETAIL_PROFILE_NOT_FOUND)
        check(Results.CARD_UNKNOWN_ERROR, Results.OPERATION_EUICC_CARD, Results.DETAIL_UNKNOWN)
        check(-99, Results.OPERATION_EUICC_CARD, Results.DETAIL_UNKNOWN)
        check(Results.CARD_TIMEOUT, Results.OPERATION_SYSTEM, Results.ERROR_TIME_OUT)
    }

    @Test
    fun transientCodesAreRetried() {
        assertTrue(Results.isTransient(Results.CARD_EUICC_NOT_FOUND))
        assertTrue(Results.isTransient(Results.CARD_UNKNOWN_ERROR))
        assertTrue(Results.isTransient(Results.CARD_TIMEOUT))
        assertFalse(Results.isTransient(Results.CARD_OK))
        assertFalse(Results.isTransient(2))
        assertFalse(Results.isTransient(Results.CARD_CALLER_NOT_ALLOWED))
        assertFalse(Results.isTransient(Results.CARD_PROFILE_DOES_NOT_EXIST))
    }
}
