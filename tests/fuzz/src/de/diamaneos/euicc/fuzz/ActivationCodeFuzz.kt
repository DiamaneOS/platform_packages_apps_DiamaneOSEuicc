// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.fuzz

import de.diamaneos.euicc.core.ActivationCode
import de.diamaneos.euicc.core.ConfirmationCode
import de.diamaneos.euicc.core.Nickname

/**
 * Activation codes from a QR code, the clipboard, an intent or typing (ActivationCode.parse and
 * fromParts), SM-DS events (fromEvent), and the other typed text (confirmation code, nickname).
 * Input: three parts, the whole code (or address), the matching ID, and other text.
 * - parse and fromParts throw only ActivationCode.Invalid.
 * - The host the consent dialog names and the download contacts is the code's own address
 *   field, lowercased in ASCII only: no other character may turn into it.
 * - The token, OID and flag are the code's fields. encoded() parses back to the same code.
 */
object ActivationCodeFuzz {
    private val TOKEN = Regex("[0-9A-Za-z-]*")
    private val OID = Regex("[0-2](\\.(0|[1-9][0-9]{0,8})){1,31}")

    @JvmStatic
    fun fuzzerTestOneInput(data: ByteArray) {
        val (a, b, c) = Parts.split(data, 3).map(::text)
        whole(a)
        whole("LPA:$a")
        parts(a, b)
        event(a, b)
        ConfirmationCode.normalise(c)?.let { code ->
            invariant(code.length in 1..32 && code.all { it.code in 0x21..0x7E }) { "confirmation code" }
            invariant(ConfirmationCode.hash(code, byteArrayOf(1)).size == 32) { "hash size" }
        }
        Nickname.normalise(c)?.let { nick ->
            invariant(nick.none { Character.isISOControl(it) } && nick.toByteArray(Charsets.UTF_8).size <= 64) { "nickname" }
            invariant(nick == nick.trim()) { "nickname not trimmed" }
        }
    }

    private fun whole(input: String) {
        val code = try {
            ActivationCode.parse(input)
        } catch (e: ActivationCode.Invalid) {
            return
        }
        var t = input.trim()
        if (t.length >= 4 && t.substring(0, 4).asciiLower() == "lpa:") t = t.substring(4)
        invariant(t.length <= ActivationCode.MAX_LENGTH) { "over-long code accepted" }
        val fields = t.split('$')
        invariant(fields.size >= 3 && fields[0] == "1") { "format" }
        checkHost(fields[1], code.smdpAddress)
        invariant(code.matchingId == fields[2] && TOKEN.matches(code.matchingId)) { "token" }
        invariant(code.smdpOid == fields.getOrNull(3)?.takeIf { it.isNotEmpty() }) { "OID field" }
        code.smdpOid?.let { invariant(OID.matches(it)) { "OID grammar" } }
        invariant(code.confirmationCodeRequired == (fields.getOrNull(4) == "1")) { "flag" }
        roundTrip(code)
    }

    private fun parts(address: String, token: String) {
        val code = try {
            ActivationCode.fromParts(address, token)
        } catch (e: ActivationCode.Invalid) {
            return
        }
        checkHost(address.trim(), code.smdpAddress)
        invariant(code.matchingId == token.trim() && TOKEN.matches(code.matchingId) && code.matchingId.length <= 255) { "token" }
        roundTrip(code)
    }

    private fun event(address: String, id: String) {
        val code = ActivationCode.fromEvent(address, id) ?: return
        checkHost(address, code.smdpAddress)
        invariant(code.matchingId == id && id.isNotEmpty()) { "event ID" }
        roundTrip(code)
    }

    private fun checkHost(field: String, host: String) {
        invariant(host.all { it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '.' }) { "host not LDH" }
        invariant(host == field.asciiLower()) { "host is not the code's address field" }
    }

    private fun roundTrip(code: ActivationCode) {
        val again = ActivationCode.parse(code.encoded())
        invariant(again.encoded() == code.encoded() && again.smdpAddress == code.smdpAddress &&
            again.matchingId == code.matchingId && again.smdpOid == code.smdpOid &&
            again.confirmationCodeRequired == code.confirmationCodeRequired) { "encoded() round trip" }
        invariant(ActivationCode.parse("LPA:" + code.encoded()).encoded() == code.encoded()) { "LPA: round trip" }
    }

    fun String.asciiLower(): String = String(CharArray(length) { i -> this[i].let { if (it in 'A'..'Z') it + 32 else it } })
}
