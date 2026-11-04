// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ServerTextTest {
    @Test
    fun keepsOrdinaryNames() {
        for (name in listOf("Travel 5 GB", "Vodafone.de", "\u0645\u0648\u0628\u0627\u064A\u0644", "\uD83C\uDDE9\uD83C\uDDEA Reise")) {
            assertEquals(name, ServerText.clean(name))
        }
    }

    @Test
    fun linesAndSpacesBecomeOneSpace() {
        assertEquals("a b", ServerText.clean(" a\n\n\r\t\u2028\u2029\u00A0\u3000 b\n"))
        assertEquals("", ServerText.clean("\n\n\n"))
        assertEquals("", ServerText.clean(null))
    }

    @Test
    fun dropsBidiFormatAndInvisibleCharacters() {
        val hidden = "\u0000\u0007\u007F\u0085\u00AD\u034F\u061C\u115F\u17B4\u180B\u200B\u200D\u200E\u202A\u202E" +
            "\u2060\u2066\u2069\u2800\u3164\uE000\uFE0F\uFEFF\uFFA0\uD800"
        assertEquals("ab", ServerText.clean("a" + hidden + "b"))
        assertEquals("", ServerText.clean(hidden))
        assertEquals("ab", ServerText.clean("a" + String(Character.toChars(0xE0041)) + String(Character.toChars(0xE0101)) + "b"))
    }

    @Test
    fun boundsLengthAndStackedMarks() {
        assertEquals(ServerText.MAX_CHARS, ServerText.clean("x".repeat(500)).length)
        val emoji = String(Character.toChars(0x1F600))
        assertEquals(emoji.repeat(4), ServerText.clean(emoji.repeat(9), 4))
        assertEquals("a\u0301\u0301\u0301b", ServerText.clean("a" + "\u0301".repeat(60) + "b"))
        assertEquals("a b", ServerText.clean("a b c", 3))
        assertTrue(ServerText.clean(" ".repeat(9) + "a").startsWith("a"))
    }
}
