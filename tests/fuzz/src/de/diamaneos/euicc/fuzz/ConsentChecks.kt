// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.fuzz

import de.diamaneos.euicc.core.ProfileMetadata
import de.diamaneos.euicc.core.ServerText

/**
 * What server text may look like once it reaches a dialog. Independent of ServerText: the
 * Unicode properties are taken from the standard (UCD DerivedCoreProperties and the bidi
 * classes), not from its code.
 */
object ConsentChecks {
    /** Default_Ignorable_Code_Point (Unicode 15.0 DerivedCoreProperties.txt). */
    private val DEFAULT_IGNORABLE = listOf(
        0x00AD..0x00AD, 0x034F..0x034F, 0x061C..0x061C, 0x115F..0x1160, 0x17B4..0x17B5,
        0x180B..0x180F, 0x200B..0x200F, 0x202A..0x202E, 0x2060..0x206F, 0x3164..0x3164,
        0xFE00..0xFE0F, 0xFEFF..0xFEFF, 0xFFA0..0xFFA0, 0xFFF0..0xFFF8, 0x1BCA0..0x1BCA3,
        0x1D173..0x1D17A, 0xE0000..0xE0FFF,
    )

    /** Characters fonts draw as blank that are not default ignorable. */
    private val BLANK = listOf(0x2800..0x2800, 0x1D159..0x1D159, 0x16FE4..0x16FE4)

    private val BIDI_CONTROL = setOf(
        Character.DIRECTIONALITY_LEFT_TO_RIGHT_EMBEDDING, Character.DIRECTIONALITY_RIGHT_TO_LEFT_EMBEDDING,
        Character.DIRECTIONALITY_LEFT_TO_RIGHT_OVERRIDE, Character.DIRECTIONALITY_RIGHT_TO_LEFT_OVERRIDE,
        Character.DIRECTIONALITY_POP_DIRECTIONAL_FORMAT, Character.DIRECTIONALITY_LEFT_TO_RIGHT_ISOLATE,
        Character.DIRECTIONALITY_RIGHT_TO_LEFT_ISOLATE, Character.DIRECTIONALITY_FIRST_STRONG_ISOLATE,
        Character.DIRECTIONALITY_POP_DIRECTIONAL_ISOLATE,
    )

    private val BAD_TYPES = setOf(
        Character.CONTROL, Character.FORMAT, Character.SURROGATE, Character.PRIVATE_USE, Character.UNASSIGNED,
        Character.LINE_SEPARATOR, Character.PARAGRAPH_SEPARATOR,
    ).map { it.toInt() }.toSet()

    /** Why [s] may not be shown, or null. [max] is the length bound in code points. */
    fun problem(s: String, max: Int): String? {
        if (s.startsWith(' ') || s.endsWith(' ') || "  " in s) return "spacing"
        if (s.codePointCount(0, s.length) > max) return "too long"
        var marks = 0
        for (c in s.codePoints()) {
            val type = Character.getType(c)
            if (type in BAD_TYPES) return "category $type U+%04X".format(c)
            if (c != 0x20 && (Character.isWhitespace(c) || Character.isSpaceChar(c))) return "space U+%04X".format(c)
            if (DEFAULT_IGNORABLE.any { c in it } || BLANK.any { c in it }) return "invisible U+%04X".format(c)
            if (Character.getDirectionality(c) in BIDI_CONTROL) return "bidi control U+%04X".format(c)
            marks = if (type == Character.NON_SPACING_MARK.toInt() || type == Character.ENCLOSING_MARK.toInt()) marks + 1 else 0
            if (marks > 3) return "stacked marks"
        }
        return null
    }

    /** The name and provider of [m], as the consent and result dialogs show them, pass [problem]. */
    fun check(m: ProfileMetadata) {
        for (text in listOf(m.profileName, m.serviceProviderName)) {
            problem(ServerText.clean(text), ServerText.MAX_CHARS)?.let { throw Violation("consent text: $it") }
        }
    }
}
