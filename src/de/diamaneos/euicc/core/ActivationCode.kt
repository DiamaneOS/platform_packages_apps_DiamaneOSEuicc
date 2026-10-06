// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.core

import java.security.MessageDigest

/**
 * An SGP.22 Activation Code (section 4.1): "1$<SM-DP+ address>$<AC_Token>[$<SM-DP+ OID>
 * [$<confirmation code required flag>]]", with an "LPA:" prefix when it comes from a QR code.
 * toString() never prints the matching ID.
 */
class ActivationCode(
    /** Lowercase FQDN; the only host the download contacts. */
    val smdpAddress: String,
    /** AC_Token (MatchingID, 4.1.1); may be empty. Secret until used: never logged. */
    val matchingId: String,
    /** SM-DP+ OID that CERT.DPauth.ECDSA must carry, if the code names one. */
    val smdpOid: String?,
    val confirmationCodeRequired: Boolean,
) {
    /** The code in its canonical form, without "LPA:"; the key that pairs a download with its consent. */
    fun encoded(): String = buildString {
        append("1$").append(smdpAddress).append('$').append(matchingId)
        if (smdpOid != null || confirmationCodeRequired) append('$').append(smdpOid.orEmpty())
        if (confirmationCodeRequired) append("$1")
    }

    override fun toString() = "ActivationCode(oid=${smdpOid != null}, cc=$confirmationCodeRequired)"

    /** Why a code was refused. Shown to the user; never contains the input. */
    enum class Problem { FORMAT, VERSION, ADDRESS, TOKEN, OID, FLAG, TOO_LONG }

    class Invalid(val problem: Problem) : Exception(problem.name)

    companion object {
        const val MAX_LENGTH = 255
        private val TOKEN = Regex("[0-9A-Za-z-]*")
        private val OID = Regex("[0-2](\\.(0|[1-9][0-9]{0,8})){1,31}")

        /** Parses a scanned or pasted code. Throws [Invalid]. */
        fun parse(input: String): ActivationCode {
            var text = input.trim()
            if (text.regionMatches(0, "LPA:", 0, 4, ignoreCase = true)) text = text.substring(4)
            if (text.length > MAX_LENGTH) throw Invalid(Problem.TOO_LONG)
            // 4.1: ignore a delimiter and any parameters after the defined ones.
            val fields = text.split('$')
            if (fields.size < 3) throw Invalid(Problem.FORMAT)
            if (fields[0] != "1") throw Invalid(Problem.VERSION)
            val address = Fqdn.normalise(fields[1]) ?: throw Invalid(Problem.ADDRESS)
            val token = fields[2]
            if (!TOKEN.matches(token)) throw Invalid(Problem.TOKEN)
            val oid = fields.getOrNull(3)?.takeIf { it.isNotEmpty() }
            if (oid != null && !OID.matches(oid)) throw Invalid(Problem.OID)
            val flag = when (fields.getOrNull(4)) {
                null, "", "0" -> false
                "1" -> true
                else -> throw Invalid(Problem.FLAG)
            }
            return ActivationCode(address, token, oid, flag)
        }

        /** Manual entry of the SM-DP+ address and the activation code (matching ID). Throws [Invalid]. */
        fun fromParts(address: String, matchingId: String): ActivationCode {
            val host = Fqdn.normalise(address.trim()) ?: throw Invalid(Problem.ADDRESS)
            val token = matchingId.trim()
            if (token.length > MAX_LENGTH || !TOKEN.matches(token)) throw Invalid(Problem.TOKEN)
            return ActivationCode(host, token, null, false)
        }

        /** An SM-DS event (3.1.3 option b): the MatchingID is the EventID. Null if either is invalid. */
        fun fromEvent(rspServerAddress: String, eventId: String): ActivationCode? {
            val host = Fqdn.normalise(rspServerAddress) ?: return null
            if (eventId.isEmpty() || eventId.length > MAX_LENGTH || !TOKEN.matches(eventId)) return null
            return ActivationCode(host, eventId, null, false)
        }
    }
}

/** Host names the download may contact: ASCII LDH FQDNs, no ports, no IP literals. */
object Fqdn {
    private val LABEL = Regex("[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")

    /** Lowercase [input] if it is a fully qualified LDH host name of two or more labels; else null. */
    fun normalise(input: String): String? {
        val host = input.lowercase(java.util.Locale.ROOT)
        if (host.isEmpty() || host.length > 253) return null
        val labels = host.split('.')
        if (labels.size < 2 || labels.any { !LABEL.matches(it) }) return null
        // A numeric last label would be an IPv4 literal, not a domain name.
        if (labels.last().all { it.isDigit() }) return null
        return host
    }

    /**
     * Whether certificate dNSName [pattern] matches [host] (RFC 6125 6.4, as SGP.22 4.5.2.1
     * allows with RFC 2818): exact, or "*" as the whole left-most label of a pattern with at
     * least three labels, matching exactly one label.
     */
    fun matches(host: String, pattern: String): Boolean {
        val h = normalise(host) ?: return false
        val p = pattern.lowercase(java.util.Locale.ROOT)
        if (!p.startsWith("*.")) return normalise(p) == h
        val suffix = normalise(p.substring(2)) ?: return false
        if (suffix.count { it == '.' } < 1) return false
        val dot = h.indexOf('.')
        return dot > 0 && h.substring(dot + 1) == suffix
    }
}

/** SGP.22 Confirmation Code (3.1.3): entered by the user, sent only as a salted hash. */
object ConfirmationCode {
    const val MAX_LENGTH = 32

    /** The code to hash: trimmed, 1 to 32 visible ASCII characters; null if not acceptable. */
    fun normalise(input: String?): String? {
        val code = input?.trim() ?: return null
        if (code.isEmpty() || code.length > MAX_LENGTH) return null
        if (code.any { it.code !in 0x21..0x7E }) return null
        return code
    }

    /** Hashed Confirmation Code = SHA256(SHA256(Confirmation Code) | TransactionID) (3.1.3). */
    fun hash(code: String, transactionId: ByteArray): ByteArray {
        val inner = MessageDigest.getInstance("SHA-256").digest(code.toByteArray(Charsets.US_ASCII))
        return MessageDigest.getInstance("SHA-256").digest(inner + transactionId)
    }
}
