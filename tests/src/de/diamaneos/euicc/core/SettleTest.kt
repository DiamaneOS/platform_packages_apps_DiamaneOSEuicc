// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.core

import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test

class SettleTest {
    private fun run(results: List<String?>, attempts: Int): Pair<String?, Int> {
        var reads = 0
        val sleeps = mutableListOf<Long>()
        val value = readUntilSettled(attempts, 1000, { sleeps.add(it) }, { results[reads++] }, { it != null })
        assertEquals(reads - 1, sleeps.size)
        return value to reads
    }

    @Test
    fun firstGoodReadReturnsAtOnce() = assertEquals("list" to 1, run(listOf("list"), 8))

    @Test
    fun retriesWhileTheCardRestarts() = assertEquals("list" to 3, run(listOf(null, null, "list"), 8))

    @Test
    fun givesUpAfterTheLastAttempt() = assertEquals(null to 3, run(listOf(null, null, null, "late"), 3))

    @Test
    fun oneAttemptNeverSleeps() = assertEquals(null to 1, run(listOf(null, "list"), 1))

    private fun retry(codes: List<Int?>, pauses: List<Long>): Triple<Int?, Int, List<Long>> {
        var calls = 0
        val sleeps = mutableListOf<Long>()
        val retried = mutableListOf<Int>()
        val code = try {
            retryWhileRestarting(pauses, { sleeps.add(it) }, { retried += it.code }) {
                codes[calls++]?.let { throw CardException(it) }
                null
            }
        } catch (e: CardException) {
            e.code
        }
        assertEquals(sleeps.size, retried.size)
        return Triple(code, calls, sleeps)
    }

    @Test
    fun transientCardFailuresAreRetried() = assertEquals(
        Triple(null, 3, listOf(2000L, 4000L)),
        retry(listOf(Results.CARD_UNKNOWN_ERROR, Results.CARD_TIMEOUT, null), listOf(2000L, 4000L, 8000L)))

    @Test
    fun anSgp22ErrorIsNotRetried() = assertEquals(Triple(127, 1, emptyList<Long>()), retry(listOf(127, null), listOf(2000L)))

    @Test
    fun theLastFailureIsThrown() = assertEquals(
        Triple(Results.CARD_EUICC_NOT_FOUND, 2, listOf(2000L)),
        retry(listOf(-1, Results.CARD_EUICC_NOT_FOUND, null), listOf(2000L)))

    @Test
    fun otherExceptionsPass() {
        try {
            retryWhileRestarting(listOf(1L), { fail("slept") }) { throw IllegalStateException() }
        } catch (e: IllegalStateException) {
            return
        }
        fail("not thrown")
    }
}
