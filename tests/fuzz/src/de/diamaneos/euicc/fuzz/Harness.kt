// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.fuzz

/** An input that breaks an invariant. Jazzer reports it like a crash. */
class Violation(message: String) : AssertionError(message)

fun invariant(condition: Boolean, message: () -> String) {
    if (!condition) throw Violation(message())
}

/**
 * Inputs made of several parts: each is a two-byte big-endian length and its bytes. A short
 * last part takes what is left, so every input splits.
 */
object Parts {
    fun split(data: ByteArray, count: Int): List<ByteArray> {
        val out = ArrayList<ByteArray>(count)
        var pos = 0
        repeat(count - 1) {
            if (pos + 2 > data.size) {
                out += ByteArray(0)
                return@repeat
            }
            val n = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)
            pos += 2
            val end = minOf(data.size, pos + n)
            out += data.copyOfRange(pos, end)
            pos = end
        }
        out += data.copyOfRange(minOf(pos, data.size), data.size)
        return out
    }

    fun join(vararg parts: ByteArray): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        parts.forEachIndexed { i, p ->
            if (i < parts.size - 1) {
                require(p.size <= 0xFFFF)
                out.write(p.size ushr 8)
                out.write(p.size and 0xFF)
            }
            out.write(p)
        }
        return out.toByteArray()
    }
}

/** A text input: the bytes as UTF-8, malformed sequences replaced. */
fun text(data: ByteArray): String = String(data, Charsets.UTF_8)

/** [block], where only IllegalArgumentException may end it. Null if it did. */
inline fun <T> orIae(block: () -> T): T? = try {
    block()
} catch (e: IllegalArgumentException) {
    null
}
