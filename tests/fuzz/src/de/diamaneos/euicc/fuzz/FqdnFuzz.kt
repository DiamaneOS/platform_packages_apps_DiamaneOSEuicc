// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.fuzz

import de.diamaneos.euicc.core.Fqdn
import de.diamaneos.euicc.fuzz.ActivationCodeFuzz.asciiLower

/**
 * Host names: Fqdn.normalise (codes, SM-DS events, the eUICC's SM-DS address, notification
 * addresses) and Fqdn.matches (certificate dNSName against the host). Input: two parts.
 * - normalise gives null or the input lowercased in ASCII, an LDH name of two or more labels.
 * - matches agrees with a reference RFC 6125 matcher written here.
 */
object FqdnFuzz {
    @JvmStatic
    fun fuzzerTestOneInput(data: ByteArray) {
        val (a, b) = Parts.split(data, 2).map(::text)
        for (s in listOf(a, b)) {
            invariant(Fqdn.normalise(s) == reference(s)) { "normalise differs from reference" }
        }
        invariant(Fqdn.matches(a, b) == referenceMatch(a, b)) { "matches differs from reference" }
        reference(a)?.let { h ->
            invariant(Fqdn.matches(h, h)) { "host does not match itself" }
            invariant(Fqdn.matches(h, "*." + h.substringAfter('.')) == (h.count { it == '.' } >= 2)) { "wildcard" }
        }
    }

    private val LABEL = Regex("[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")

    fun reference(input: String): String? {
        if (input.any { it.code > 0x7F }) return null
        val h = input.asciiLower()
        if (h.isEmpty() || h.length > 253) return null
        val labels = h.split('.')
        if (labels.size < 2 || !labels.all { LABEL.matches(it) }) return null
        if (labels.last().all { it in '0'..'9' }) return null
        return h
    }

    private fun referenceMatch(host: String, pattern: String): Boolean {
        val h = reference(host) ?: return false
        if (pattern.any { it.code > 0x7F }) return false
        val p = pattern.asciiLower()
        if (!p.startsWith("*.")) return reference(p) == h
        val suffix = reference(p.substring(2)) ?: return false
        val first = h.substringBefore('.')
        return first.isNotEmpty() && h.substring(first.length + 1) == suffix
    }
}
