// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.core

import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction

/** A parsed JSON value (RFC 8259). */
sealed interface JsonValue

class JsonObject(val members: Map<String, JsonValue>) : JsonValue {
    fun string(name: String): String? = (members[name] as? JsonString)?.value
    fun obj(name: String): JsonObject? = members[name] as? JsonObject
    fun array(name: String): JsonArray? = members[name] as? JsonArray
}

class JsonArray(val items: List<JsonValue>) : JsonValue

class JsonString(val value: String) : JsonValue

/** A number, kept as its text: ES9+ uses none, so nothing converts it. */
class JsonNumber(val text: String) : JsonValue

class JsonBool(val value: Boolean) : JsonValue

object JsonNull : JsonValue

/** Malformed or over-limit JSON. The message never contains input text. */
class JsonException(message: String) : Exception(message)

/** Bounds on what a response may contain. */
class JsonLimits(
    val maxDepth: Int = 8,
    val maxStringChars: Int = 64 * 1024,
    val maxMembers: Int = 64,
    val maxItems: Int = 64,
)

/**
 * A strict JSON parser and the writer for ES9+ requests. Strict: UTF-8 only, no BOM, no
 * comments, no trailing commas, no single quotes, no duplicate member names, no lone
 * surrogates, no raw control characters, nothing after the value, and every limit enforced.
 */
object Json {
    fun parse(bytes: ByteArray, limits: JsonLimits = JsonLimits()): JsonValue {
        val text = try {
            Charsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes))
                .toString()
        } catch (e: CharacterCodingException) {
            throw JsonException("not UTF-8")
        }
        return parse(text, limits)
    }

    fun parse(text: String, limits: JsonLimits = JsonLimits()): JsonValue = Parser(text, limits).document()

    /** The top-level value, which must be an object. */
    fun parseObject(bytes: ByteArray, limits: JsonLimits = JsonLimits()): JsonObject =
        parse(bytes, limits) as? JsonObject ?: throw JsonException("not an object")

    /**
     * Writes an object of strings, nested maps and lists. Only the characters JSON requires
     * are escaped (SGP.22 6.5): quotation mark, reverse solidus and control characters.
     */
    fun write(value: Map<String, Any?>): String = StringBuilder().also { writeValue(it, value) }.toString()

    private fun writeValue(out: StringBuilder, value: Any?) {
        when (value) {
            null -> out.append("null")
            is String -> writeString(out, value)
            is Boolean -> out.append(value)
            is Int -> out.append(value)
            is Map<*, *> -> {
                out.append('{')
                value.entries.forEachIndexed { i, (k, v) ->
                    if (i > 0) out.append(',')
                    writeString(out, k as String)
                    out.append(':')
                    writeValue(out, v)
                }
                out.append('}')
            }
            is List<*> -> {
                out.append('[')
                value.forEachIndexed { i, v ->
                    if (i > 0) out.append(',')
                    writeValue(out, v)
                }
                out.append(']')
            }
            else -> throw IllegalArgumentException("unsupported JSON value")
        }
    }

    private fun writeString(out: StringBuilder, s: String) {
        out.append('"')
        for (c in s) {
            when {
                c == '"' -> out.append("\\\"")
                c == '\\' -> out.append("\\\\")
                c == '\n' -> out.append("\\n")
                c == '\r' -> out.append("\\r")
                c == '\t' -> out.append("\\t")
                c == '\b' -> out.append("\\b")
                c == '\u000C' -> out.append("\\f")
                c.code < 0x20 -> out.append(String.format(java.util.Locale.ROOT, "\\u%04x", c.code))
                else -> out.append(c)
            }
        }
        out.append('"')
    }

    private class Parser(private val s: String, private val limits: JsonLimits) {
        private var pos = 0

        fun document(): JsonValue {
            skipSpace()
            val value = value(0)
            skipSpace()
            if (pos != s.length) fail("trailing data")
            return value
        }

        private fun value(depth: Int): JsonValue {
            if (depth > limits.maxDepth) fail("too deep")
            if (pos >= s.length) fail("unexpected end")
            return when (val c = s[pos]) {
                '{' -> obj(depth)
                '[' -> array(depth)
                '"' -> JsonString(string())
                't' -> literal("true", JsonBool(true))
                'f' -> literal("false", JsonBool(false))
                'n' -> literal("null", JsonNull)
                else -> if (c == '-' || c in '0'..'9') number() else fail("unexpected character")
            }
        }

        private fun obj(depth: Int): JsonObject {
            pos++ // {
            val members = LinkedHashMap<String, JsonValue>()
            skipSpace()
            if (peek() == '}') {
                pos++
                return JsonObject(members)
            }
            while (true) {
                skipSpace()
                if (peek() != '"') fail("expected a member name")
                val name = string()
                skipSpace()
                expect(':')
                skipSpace()
                val value = value(depth + 1)
                if (members.put(name, value) != null) fail("duplicate member")
                if (members.size > limits.maxMembers) fail("too many members")
                skipSpace()
                when (next()) {
                    ',' -> continue
                    '}' -> return JsonObject(members)
                    else -> fail("expected , or }")
                }
            }
        }

        private fun array(depth: Int): JsonArray {
            pos++ // [
            val items = ArrayList<JsonValue>()
            skipSpace()
            if (peek() == ']') {
                pos++
                return JsonArray(items)
            }
            while (true) {
                skipSpace()
                items += value(depth + 1)
                if (items.size > limits.maxItems) fail("too many items")
                skipSpace()
                when (next()) {
                    ',' -> continue
                    ']' -> return JsonArray(items)
                    else -> fail("expected , or ]")
                }
            }
        }

        private fun string(): String {
            pos++ // opening quote
            val out = StringBuilder()
            while (true) {
                if (pos >= s.length) fail("unterminated string")
                val c = s[pos++]
                when {
                    c == '"' -> return out.toString()
                    c == '\\' -> escape(out)
                    c.code < 0x20 -> fail("control character in string")
                    Character.isSurrogate(c) -> {
                        // A pair arrives as two chars; a lone surrogate cannot come from UTF-8,
                        // but check anyway.
                        if (!Character.isHighSurrogate(c) || pos >= s.length || !Character.isLowSurrogate(s[pos])) {
                            fail("lone surrogate")
                        }
                        out.append(c).append(s[pos++])
                    }
                    else -> out.append(c)
                }
                if (out.length > limits.maxStringChars) fail("string too long")
            }
        }

        private fun escape(out: StringBuilder) {
            if (pos >= s.length) fail("unterminated escape")
            when (s[pos++]) {
                '"' -> out.append('"')
                '\\' -> out.append('\\')
                '/' -> out.append('/')
                'b' -> out.append('\b')
                'f' -> out.append('\u000C')
                'n' -> out.append('\n')
                'r' -> out.append('\r')
                't' -> out.append('\t')
                'u' -> {
                    val unit = hex4()
                    if (Character.isHighSurrogate(unit)) {
                        if (pos + 6 > s.length || s[pos] != '\\' || s[pos + 1] != 'u') fail("lone surrogate")
                        pos += 2
                        val low = hex4()
                        if (!Character.isLowSurrogate(low)) fail("lone surrogate")
                        out.append(unit).append(low)
                    } else if (Character.isLowSurrogate(unit)) {
                        fail("lone surrogate")
                    } else {
                        out.append(unit)
                    }
                }
                else -> fail("bad escape")
            }
        }

        private fun hex4(): Char {
            if (pos + 4 > s.length) fail("bad escape")
            var v = 0
            repeat(4) {
                val d = Character.digit(s[pos++], 16)
                if (d < 0) fail("bad escape")
                v = (v shl 4) or d
            }
            return v.toChar()
        }

        private fun number(): JsonNumber {
            val start = pos
            if (peek() == '-') pos++
            when {
                peek() == '0' -> pos++
                peek() in '1'..'9' -> while (peek() in '0'..'9') pos++
                else -> fail("bad number")
            }
            if (peek() == '.') {
                pos++
                if (peek() !in '0'..'9') fail("bad number")
                while (peek() in '0'..'9') pos++
            }
            if (peek() == 'e' || peek() == 'E') {
                pos++
                if (peek() == '+' || peek() == '-') pos++
                if (peek() !in '0'..'9') fail("bad number")
                while (peek() in '0'..'9') pos++
            }
            if (pos - start > 32) fail("number too long")
            return JsonNumber(s.substring(start, pos))
        }

        private fun literal(word: String, value: JsonValue): JsonValue {
            if (!s.startsWith(word, pos)) fail("bad literal")
            pos += word.length
            return value
        }

        private fun skipSpace() {
            while (pos < s.length && (s[pos] == ' ' || s[pos] == '\t' || s[pos] == '\n' || s[pos] == '\r')) pos++
        }

        private fun peek(): Char = if (pos < s.length) s[pos] else '\u0000'

        private fun next(): Char = if (pos < s.length) s[pos++] else fail("unexpected end")

        private fun expect(c: Char) {
            if (next() != c) fail("expected $c")
        }

        private fun fail(reason: String): Nothing = throw JsonException(reason)
    }
}
