// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.core

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction

/**
 * A BER-TLV element: tag (all tag bytes, big-endian) and value. Enough BER for SGP.22 data
 * (ITU-T X.690 with definite lengths; DER as SGP.22 requires).
 */
class Tlv(val tag: Int, val value: ByteArray) {
    /** Bit 6 of the first tag byte. */
    val constructed: Boolean get() = firstTagByte(tag) and 0x20 != 0

    fun children(): List<Tlv> = parse(value)

    fun child(tag: Int): Tlv? = children().firstOrNull { it.tag == tag }

    fun require(tag: Int): Tlv = child(tag) ?: throw IllegalArgumentException("missing tag")

    /** The element as bytes: tag, DER length, value. */
    fun encoded(): ByteArray = Der.tlv(tag, value)

    /** INTEGER contents, at most four bytes, two's complement. */
    fun int(): Int {
        require(value.size in 1..4) { "bad integer" }
        var result = value[0].toInt() // sign-extends
        for (i in 1 until value.size) result = (result shl 8) or (value[i].toInt() and 0xFF)
        return result
    }

    /** BOOLEAN contents: one byte, zero is false. */
    fun bool(): Boolean {
        require(value.size == 1) { "bad boolean" }
        return value[0].toInt() != 0
    }

    /** BIT STRING contents. */
    fun bits(): BitString {
        require(value.isNotEmpty()) { "bad bit string" }
        val unused = value[0].toInt() and 0xFF
        require(unused <= 7 && (unused == 0 || value.size > 1)) { "bad bit string" }
        return BitString(value.copyOfRange(1, value.size), unused)
    }

    /** UTF8String contents; malformed UTF-8 is an error. */
    fun utf8(): String = try {
        Charsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(value))
            .toString()
    } catch (e: CharacterCodingException) {
        throw IllegalArgumentException("bad UTF-8")
    }

    /** OBJECT IDENTIFIER contents in dotted form. */
    fun oid(): String = Der.decodeOid(value)

    companion object {
        /**
         * The elements in [data] at one level. Throws IllegalArgumentException on malformed
         * input: truncated tag, length or value, indefinite or over-long lengths, tags over
         * three bytes.
         */
        fun parse(data: ByteArray): List<Tlv> {
            val result = ArrayList<Tlv>()
            var pos = 0
            while (pos < data.size) {
                var tag = byteAt(data, pos++)
                if (tag and 0x1F == 0x1F) {
                    var count = 0
                    do {
                        val next = byteAt(data, pos++)
                        tag = (tag shl 8) or next
                        require(++count <= 2) { "tag too long" }
                    } while (next and 0x80 != 0)
                }
                var length = byteAt(data, pos++)
                if (length and 0x80 != 0) {
                    val count = length and 0x7F
                    require(count in 1..3) { "unsupported length" }
                    length = 0
                    repeat(count) { length = (length shl 8) or byteAt(data, pos++) }
                }
                require(length <= data.size - pos) { "truncated value" }
                result += Tlv(tag, data.copyOfRange(pos, pos + length))
                pos += length
            }
            return result
        }

        /** Exactly one element that fills [data]. */
        fun one(data: ByteArray): Tlv {
            val elements = parse(data)
            require(elements.size == 1) { "expected one element" }
            return elements[0]
        }

        /** [one], and its tag must be [tag]. */
        fun one(data: ByteArray, tag: Int): Tlv {
            val element = one(data)
            require(element.tag == tag) { "unexpected tag" }
            return element
        }

        internal fun firstTagByte(tag: Int): Int = when {
            tag > 0xFFFF -> tag ushr 16
            tag > 0xFF -> tag ushr 8
            else -> tag
        }

        private fun byteAt(data: ByteArray, pos: Int): Int {
            require(pos < data.size) { "truncated" }
            return data[pos].toInt() and 0xFF
        }
    }
}

/** BIT STRING bits; bit 0 is the most significant bit of the first byte (X.690 8.6). */
class BitString(private val bytes: ByteArray, private val unused: Int) {
    val size: Int get() = bytes.size * 8 - unused

    operator fun get(bit: Int): Boolean {
        if (bit < 0 || bit >= size) return false
        return (bytes[bit / 8].toInt() shr (7 - bit % 8)) and 1 != 0
    }

    /** Bits 0..30 as an int, bit n of the string at 1 shl n. */
    fun toFlags(): Int {
        var flags = 0
        for (bit in 0 until minOf(size, 31)) if (get(bit)) flags = flags or (1 shl bit)
        return flags
    }
}

/** DER encoding of the few element types the tests and SGP.22 parsing need. */
object Der {
    fun tlv(tag: Int, value: ByteArray): ByteArray {
        val out = ByteArrayOutputStream(value.size + 8)
        when {
            tag > 0xFFFF -> { out.write(tag ushr 16); out.write(tag ushr 8 and 0xFF); out.write(tag and 0xFF) }
            tag > 0xFF -> { out.write(tag ushr 8); out.write(tag and 0xFF) }
            else -> out.write(tag)
        }
        val n = value.size
        when {
            n < 0x80 -> out.write(n)
            n <= 0xFF -> { out.write(0x81); out.write(n) }
            n <= 0xFFFF -> { out.write(0x82); out.write(n ushr 8); out.write(n and 0xFF) }
            else -> {
                require(n <= 0xFFFFFF) { "too long" }
                out.write(0x83); out.write(n ushr 16); out.write(n ushr 8 and 0xFF); out.write(n and 0xFF)
            }
        }
        out.write(value)
        return out.toByteArray()
    }

    fun tlv(tag: Int, vararg children: ByteArray): ByteArray = tlv(tag, concat(*children))

    fun int(value: Int, tag: Int = 0x02): ByteArray {
        var bytes = byteArrayOf((value ushr 24).toByte(), (value ushr 16).toByte(), (value ushr 8).toByte(), value.toByte())
        while (bytes.size > 1 &&
            ((bytes[0].toInt() == 0 && bytes[1].toInt() and 0x80 == 0) ||
                (bytes[0].toInt() == -1 && bytes[1].toInt() and 0x80 != 0))) {
            bytes = bytes.copyOfRange(1, bytes.size)
        }
        return tlv(tag, bytes)
    }

    fun utf8(value: String, tag: Int = 0x0C): ByteArray = tlv(tag, value.toByteArray(Charsets.UTF_8))

    fun bool(value: Boolean, tag: Int = 0x01): ByteArray = tlv(tag, byteArrayOf(if (value) -1 else 0))

    /** A BIT STRING with bits [set] (bit 0 = most significant bit of the first byte). */
    fun bits(size: Int, vararg set: Int, tag: Int = 0x03): ByteArray {
        val bytes = ByteArray((size + 7) / 8)
        for (bit in set) bytes[bit / 8] = (bytes[bit / 8].toInt() or (0x80 ushr (bit % 8))).toByte()
        val unused = bytes.size * 8 - size
        return tlv(tag, byteArrayOf(unused.toByte()) + bytes)
    }

    fun oid(dotted: String, tag: Int = 0x06): ByteArray {
        val parts = dotted.split('.').map { it.toLong() }
        require(parts.size >= 2 && parts[0] in 0..2) { "bad OID" }
        val out = ByteArrayOutputStream()
        writeBase128(out, parts[0] * 40 + parts[1])
        for (i in 2 until parts.size) writeBase128(out, parts[i])
        return tlv(tag, out.toByteArray())
    }

    /** OBJECT IDENTIFIER contents to dotted form; non-minimal or over-long arcs are errors. */
    fun decodeOid(value: ByteArray): String {
        require(value.isNotEmpty() && value.size <= 64) { "bad OID" }
        val arcs = ArrayList<Long>()
        var current = 0L
        var started = false
        for ((i, b) in value.withIndex()) {
            val v = b.toInt() and 0xFF
            require(started || v != 0x80) { "non-minimal OID arc" }
            started = true
            require(current < (1L shl 49)) { "OID arc too large" }
            current = (current shl 7) or (v and 0x7F).toLong()
            if (v and 0x80 == 0) {
                arcs += current
                current = 0
                started = false
            } else {
                require(i < value.size - 1) { "truncated OID" }
            }
        }
        val first = arcs[0]
        val head = when {
            first < 40 -> listOf(0L, first)
            first < 80 -> listOf(1L, first - 40)
            else -> listOf(2L, first - 80)
        }
        return (head + arcs.drop(1)).joinToString(".")
    }

    fun concat(vararg parts: ByteArray): ByteArray {
        val out = ByteArrayOutputStream(parts.sumOf { it.size })
        parts.forEach { out.write(it) }
        return out.toByteArray()
    }

    private fun writeBase128(out: ByteArrayOutputStream, value: Long) {
        require(value >= 0) { "bad OID" }
        var shift = 63 - java.lang.Long.numberOfLeadingZeros(value or 1)
        shift -= shift % 7
        while (shift > 0) {
            out.write(((value ushr shift) and 0x7F or 0x80).toInt())
            shift -= 7
        }
        out.write((value and 0x7F).toInt())
    }
}

/** Lowercase hex, for keys and JSON; never for identifiers in logs. */
object Hex {
    private const val DIGITS = "0123456789abcdef"

    fun encode(bytes: ByteArray): String {
        val chars = CharArray(bytes.size * 2)
        bytes.forEachIndexed { i, b ->
            chars[2 * i] = DIGITS[(b.toInt() shr 4) and 0xF]
            chars[2 * i + 1] = DIGITS[b.toInt() and 0xF]
        }
        return String(chars)
    }

    /** Even-length hex in either case to bytes; null if malformed. */
    fun decode(text: String): ByteArray? {
        if (text.length % 2 != 0) return null
        val out = ByteArray(text.length / 2)
        for (i in out.indices) {
            val hi = Character.digit(text[2 * i], 16)
            val lo = Character.digit(text[2 * i + 1], 16)
            if (hi < 0 || lo < 0) return null
            out[i] = ((hi shl 4) or lo).toByte()
        }
        return out
    }
}

/** ITU-T E.118 ICCIDs as SGP.22 encodes them (Iccid, tag '5A'): BCD with swapped nibbles. */
object Iccid {
    /** The ICCID digits, trailing 'F' filler removed; null unless it is 18 to 22 digits. */
    fun decode(bytes: ByteArray): String? {
        val digits = StringBuilder(bytes.size * 2)
        var filler = false
        for (b in bytes) {
            for (nibble in intArrayOf(b.toInt() and 0xF, (b.toInt() shr 4) and 0xF)) {
                when {
                    nibble == 0xF -> filler = true
                    filler || nibble > 9 -> return null
                    else -> digits.append(('0'.code + nibble).toChar())
                }
            }
        }
        return if (digits.length in 18..22) digits.toString() else null
    }
}
