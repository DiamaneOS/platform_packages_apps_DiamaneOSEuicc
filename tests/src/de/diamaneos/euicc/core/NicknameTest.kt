// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class NicknameTest {
    @Test
    fun trimsAndClears() {
        assertEquals("Travel", Nickname.normalise("  Travel "))
        assertEquals("", Nickname.normalise(null))
        assertEquals("", Nickname.normalise("   "))
    }

    @Test
    fun countsUtf8Bytes() {
        assertEquals(64, Nickname.normalise("a".repeat(64))!!.length)
        assertNull(Nickname.normalise("a".repeat(65)))
        // The euro sign is three bytes in UTF-8.
        assertEquals(21, Nickname.normalise("€".repeat(21))!!.length)
        assertNull(Nickname.normalise("€".repeat(22)))
    }

    @Test
    fun refusesControlCharacters() {
        assertNull(Nickname.normalise("a\nb"))
        assertNull(Nickname.normalise("a\u0000b"))
    }
}
