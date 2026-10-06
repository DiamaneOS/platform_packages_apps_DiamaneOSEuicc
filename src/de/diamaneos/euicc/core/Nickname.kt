// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.core

/** SGP.22 ProfileNickname: UTF8String (SIZE(0..64)), counted in bytes. */
object Nickname {
    const val MAX_BYTES = 64

    /**
     * The nickname to store: trimmed; null or blank clears it (empty string). Returns null if
     * it is longer than 64 UTF-8 bytes or contains control characters.
     */
    fun normalise(input: String?): String? {
        val nickname = input?.trim().orEmpty()
        if (nickname.any { Character.isISOControl(it) }) return null
        if (nickname.toByteArray(Charsets.UTF_8).size > MAX_BYTES) return null
        return nickname
    }
}
