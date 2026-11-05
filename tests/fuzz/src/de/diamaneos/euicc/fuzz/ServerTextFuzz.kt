// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.fuzz

import de.diamaneos.euicc.core.ServerText

/**
 * ServerText.clean on any text, with any bound. Input: a length byte, then UTF-16BE code units
 * (so lone surrogates and every code point are reachable).
 * - The result passes ConsentChecks within the bound.
 * - Cleaning is idempotent, and keeps the visible characters in order (a subsequence).
 */
object ServerTextFuzz {
    @JvmStatic
    fun fuzzerTestOneInput(data: ByteArray) {
        if (data.isEmpty()) return
        val max = (data[0].toInt() and 0xFF) % 300
        val units = CharArray((data.size - 1) / 2) { i -> (((data[1 + 2 * i].toInt() and 0xFF) shl 8) or (data[2 + 2 * i].toInt() and 0xFF)).toChar() }
        val input = String(units)
        val out = ServerText.clean(input, max)
        ConsentChecks.problem(out, maxOf(max, 0))?.let { throw Violation("cleaned text: $it") }
        invariant(ServerText.clean(out, max) == out) { "not idempotent" }
        val kept = out.codePoints().filter { it != 0x20 }.toArray()
        val src = input.codePoints().toArray()
        var j = 0
        for (c in src) if (j < kept.size && kept[j] == c) j++
        invariant(j == kept.size) { "characters added or reordered" }
        // The default bound.
        val d = ServerText.clean(input)
        ConsentChecks.problem(d, ServerText.MAX_CHARS)?.let { throw Violation("cleaned text: $it") }
    }
}
