// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.core

import org.junit.Assert.assertEquals
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
}
