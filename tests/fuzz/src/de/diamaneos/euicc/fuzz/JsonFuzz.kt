// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.fuzz

import de.diamaneos.euicc.core.Es9
import de.diamaneos.euicc.core.Json
import de.diamaneos.euicc.core.JsonArray
import de.diamaneos.euicc.core.JsonBool
import de.diamaneos.euicc.core.JsonException
import de.diamaneos.euicc.core.JsonLimits
import de.diamaneos.euicc.core.JsonNull
import de.diamaneos.euicc.core.JsonNumber
import de.diamaneos.euicc.core.JsonObject
import de.diamaneos.euicc.core.JsonString
import de.diamaneos.euicc.core.JsonValue

/**
 * Json.parse with the ES9+ limits.
 * - Only JsonException may come out.
 * - Accepted documents respect every limit, and serialise to text that parses to the same value
 *   (the writer below is independent of Json.write).
 * - Accepted input is strict RFC 8259: the bytes are UTF-8 and re-reading the value from the
 *   reference serialisation gives the same tree.
 */
object JsonFuzz {
    private val LIMITS: JsonLimits = Es9.LIMITS

    @JvmStatic
    fun fuzzerTestOneInput(data: ByteArray) {
        val value = try {
            Json.parse(data, LIMITS)
        } catch (e: JsonException) {
            return
        }
        invariant(depth(value) <= LIMITS.maxDepth) { "depth limit" }
        checkLimits(value)
        val text = serialise(value)
        val again = try {
            Json.parse(text.toByteArray(Charsets.UTF_8), JsonLimits(maxDepth = 64, maxStringChars = Int.MAX_VALUE, maxMembers = Int.MAX_VALUE, maxItems = Int.MAX_VALUE))
        } catch (e: JsonException) {
            throw Violation("re-serialised value does not parse: ${e.message}")
        }
        invariant(serialise(again) == text) { "round trip differs" }
        // The input itself is UTF-8: decoding it again must give the same characters.
        invariant(String(data, Charsets.UTF_8).toByteArray(Charsets.UTF_8).contentEquals(data)) { "not UTF-8 accepted" }
    }

    /** The deepest value's level, the top value at 0 (as JsonLimits.maxDepth counts). */
    private fun depth(v: JsonValue): Int = when (v) {
        is JsonObject -> v.members.values.maxOfOrNull { 1 + depth(it) } ?: 0
        is JsonArray -> v.items.maxOfOrNull { 1 + depth(it) } ?: 0
        else -> 0
    }

    private fun checkLimits(v: JsonValue) {
        when (v) {
            is JsonObject -> {
                invariant(v.members.size <= LIMITS.maxMembers) { "member limit" }
                v.members.forEach { (k, m) ->
                    invariant(k.length <= LIMITS.maxStringChars) { "name limit" }
                    checkLimits(m)
                }
            }
            is JsonArray -> {
                invariant(v.items.size <= LIMITS.maxItems) { "item limit" }
                v.items.forEach { checkLimits(it) }
            }
            is JsonString -> {
                invariant(v.value.length <= LIMITS.maxStringChars) { "string limit" }
                var i = 0
                while (i < v.value.length) {
                    val c = v.value[i]
                    if (Character.isHighSurrogate(c)) {
                        invariant(i + 1 < v.value.length && Character.isLowSurrogate(v.value[i + 1])) { "lone surrogate" }
                        i++
                    } else {
                        invariant(!Character.isLowSurrogate(c)) { "lone surrogate" }
                    }
                    i++
                }
            }
            is JsonNumber -> invariant(NUMBER.matches(v.text) && v.text.length <= 32) { "number grammar" }
            else -> {}
        }
    }

    private val NUMBER = Regex("-?(0|[1-9][0-9]*)(\\.[0-9]+)?([eE][+-]?[0-9]+)?")

    fun serialise(v: JsonValue): String = StringBuilder().also { write(it, v) }.toString()

    private fun write(out: StringBuilder, v: JsonValue) {
        when (v) {
            is JsonObject -> {
                out.append('{')
                v.members.entries.forEachIndexed { i, (k, m) ->
                    if (i > 0) out.append(',')
                    str(out, k)
                    out.append(':')
                    write(out, m)
                }
                out.append('}')
            }
            is JsonArray -> {
                out.append('[')
                v.items.forEachIndexed { i, m ->
                    if (i > 0) out.append(',')
                    write(out, m)
                }
                out.append(']')
            }
            is JsonString -> str(out, v.value)
            is JsonNumber -> out.append(v.text)
            is JsonBool -> out.append(v.value)
            JsonNull -> out.append("null")
        }
    }

    private fun str(out: StringBuilder, s: String) {
        out.append('"')
        for (c in s) {
            if (c == '"' || c == '\\' || c.code < 0x20) out.append("\\u%04x".format(c.code)) else out.append(c)
        }
        out.append('"')
    }
}
