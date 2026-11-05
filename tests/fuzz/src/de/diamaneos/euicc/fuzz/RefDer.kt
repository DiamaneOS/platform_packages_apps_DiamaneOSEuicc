// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.fuzz

/**
 * An independent X.690 decoder for the oracles, written from the standard and not from Ber.kt.
 * It reports how an encoding departs from DER instead of normalising it, so a target can tell
 * an ambiguous encoding (two readers could disagree) from a merely non-minimal one.
 */
object RefDer {
    class Bad(val reason: String) : Exception(reason)

    class Node(
        val tagClass: Int,
        val constructed: Boolean,
        val number: Long,
        /** The tag bytes as Ber.kt packs them (big-endian int), or -1 if over three bytes. */
        val packedTag: Int,
        val content: ByteArray,
        /** The header used a longer length form than DER allows. */
        val longLength: Boolean,
        /** The tag used a form X.690 8.1.2 forbids (high form below 31, or a leading 0x80). */
        val badTag: Boolean,
    ) {
        fun children(): List<Node> = decode(content)
    }

    fun decode(data: ByteArray): List<Node> {
        val out = ArrayList<Node>()
        var pos = 0
        fun next(): Int {
            if (pos >= data.size) throw Bad("truncated")
            return data[pos++].toInt() and 0xFF
        }
        while (pos < data.size) {
            val start = pos
            val first = next()
            var number = (first and 0x1F).toLong()
            var badTag = false
            if (number == 0x1FL) {
                number = 0
                var count = 0
                while (true) {
                    val b = next()
                    if (count == 0 && b == 0x80) badTag = true
                    count++
                    if (count > 4) throw Bad("tag too long")
                    number = (number shl 7) or (b and 0x7F).toLong()
                    if (b and 0x80 == 0) break
                }
                if (number < 31) badTag = true
            }
            val tagLen = pos - start
            var packed = -1
            if (tagLen <= 3) {
                packed = 0
                for (i in start until pos) packed = (packed shl 8) or (data[i].toInt() and 0xFF)
            }
            val l0 = next()
            var length: Long
            var longLength = false
            if (l0 < 0x80) {
                length = l0.toLong()
            } else if (l0 == 0x80) {
                throw Bad("indefinite length")
            } else {
                val n = l0 and 0x7F
                if (n > 4) throw Bad("length too long")
                length = 0
                repeat(n) { length = (length shl 8) or next().toLong() }
                val minimal = when {
                    length < 0x80 -> 0
                    length <= 0xFF -> 1
                    length <= 0xFFFF -> 2
                    length <= 0xFFFFFF -> 3
                    else -> 4
                }
                if (n != minimal) longLength = true
            }
            if (length > data.size - pos) throw Bad("truncated value")
            val content = data.copyOfRange(pos, pos + length.toInt())
            pos += length.toInt()
            out += Node(first ushr 6, first and 0x20 != 0, number, packed, content, longLength, badTag)
        }
        return out
    }

    /** Every tag in [data], at every level that parses as constructed, is in a form X.690 allows. */
    fun tagsCanonical(data: ByteArray, depth: Int = 0): Boolean {
        val nodes = try { decode(data) } catch (e: Bad) { return true }
        for (n in nodes) {
            if (n.badTag) return false
            if (n.constructed && depth < 64 && !tagsCanonical(n.content, depth + 1)) return false
        }
        return true
    }

    /** DER INTEGER contents: minimal two's complement. */
    fun intMinimal(v: ByteArray): Boolean =
        v.isNotEmpty() && !(v.size > 1 && ((v[0].toInt() == 0 && v[1].toInt() and 0x80 == 0) ||
            (v[0].toInt() == -1 && v[1].toInt() and 0x80 != 0)))

    /** DER BIT STRING contents: the unused bits are zero. Returns the set bit numbers. */
    fun bits(v: ByteArray): Set<Int>? {
        if (v.isEmpty()) return null
        val unused = v[0].toInt() and 0xFF
        if (unused > 7 || (unused > 0 && v.size == 1)) return null
        if (v.size > 1 && (v.last().toInt() and ((1 shl unused) - 1)) != 0) return null
        val set = HashSet<Int>()
        for (i in 1 until v.size) for (b in 0 until 8) {
            if ((v[i].toInt() shr (7 - b)) and 1 != 0) set += (i - 1) * 8 + b
        }
        return set
    }

    /** Every bit a reader that ignores the unused-bits count would see. */
    fun bitsIgnoringUnused(v: ByteArray): Set<Int> {
        val set = HashSet<Int>()
        for (i in 1 until v.size) for (b in 0 until 8) {
            if ((v[i].toInt() shr (7 - b)) and 1 != 0) set += (i - 1) * 8 + b
        }
        return set
    }

    /** The same element as Ber.kt would see it under another reader: tag number and class. */
    fun key(n: Node): Long = (n.tagClass.toLong() shl 40) or (if (n.constructed) 1L shl 39 else 0) or n.number
}
