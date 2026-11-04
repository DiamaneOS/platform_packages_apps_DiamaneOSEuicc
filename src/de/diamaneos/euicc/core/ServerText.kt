// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.core

/**
 * Text that an RSP server chose, as the screen shows it: one line of visible characters, so it
 * cannot reorder, hide or push away the lines around it.
 */
object ServerText {
    /** The longest name SGP.22 allows (ProfileName, ProfileNickname). */
    const val MAX_CHARS = 64

    /** The longest address (an FQDN). */
    const val MAX_ADDRESS_CHARS = 255

    /** Enough stacked marks for real scripts, too few to draw over the next line. */
    private const val MAX_MARKS = 3

    /** Invisible characters outside the categories [clean] drops. */
    private val INVISIBLE = listOf(
        0x034F..0x034F, 0x115F..0x1160, 0x17B4..0x17B5, 0x180B..0x180F, 0x2800..0x2800,
        0x3164..0x3164, 0xFE00..0xFE0F, 0xFFA0..0xFFA0, 0xE0000..0xE0FFF,
    )

    /**
     * Without control, format, separator, private use and invisible characters, among them
     * every bidi control. Runs of space become one space. At most [max] characters.
     */
    fun clean(input: String?, max: Int = MAX_CHARS): String {
        val out = StringBuilder()
        var count = 0
        var marks = 0
        var space = false
        input.orEmpty().codePoints().forEach { c ->
            if (Character.isWhitespace(c) || Character.isSpaceChar(c)) {
                space = true
                return@forEach
            }
            val type = Character.getType(c).toByte()
            if (type in DROPPED || INVISIBLE.any { c in it } || count >= max) return@forEach
            val mark = type == Character.NON_SPACING_MARK || type == Character.ENCLOSING_MARK
            marks = if (mark) marks + 1 else 0
            if (marks > MAX_MARKS) return@forEach
            if (space && out.isNotEmpty() && count + 1 < max) {
                out.append(' ')
                count++
            }
            space = false
            out.appendCodePoint(c)
            count++
        }
        return out.toString()
    }

    private val DROPPED = setOf(
        Character.CONTROL, Character.FORMAT, Character.SURROGATE, Character.PRIVATE_USE, Character.UNASSIGNED,
    )
}
