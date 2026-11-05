// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.fuzz

import de.diamaneos.euicc.core.Es9
import de.diamaneos.euicc.core.Failure
import de.diamaneos.euicc.core.Fqdn
import de.diamaneos.euicc.core.Json
import de.diamaneos.euicc.core.JsonException
import de.diamaneos.euicc.core.JsonObject
import de.diamaneos.euicc.core.ProfileMetadata
import de.diamaneos.euicc.core.Results
import de.diamaneos.euicc.core.RspException
import de.diamaneos.euicc.core.Tlv

/**
 * The ES9+ and ES11 response parsers (Es9.kt) on a response body, as HttpsRspServer reads it:
 * strict JSON with the function's limits, then the function's parser.
 * - Only JsonException and RspException (INVALID_RESPONSE or SERVER_REFUSED) may come out.
 * - Status codes that reach the result are well formed and map to a result code.
 * - Every binary member is one TLV with the expected tag.
 * - Transaction IDs are 1 to 16 bytes. Events are at most 16, with valid hosts and IDs.
 */
object Es9Fuzz {
    private val STATUS = Regex("[0-9]{1,3}(\\.[0-9]{1,3}){0,5}")

    @JvmStatic
    fun fuzzerTestOneInput(data: ByteArray) {
        val normal = parse(data, false)
        val bpp = parse(data, true)
        if (normal != null) {
            run { Es9.parseInitiateAuthentication(normal) }?.let { r ->
                txid(r.transactionId)
                one("serverSigned1", r.serverSigned1, 0x30)
                one("serverSignature1", r.serverSignature1, 0x5F37)
                one("euiccCiPkIdToBeUsed", r.euiccCiPkIdToBeUsed, 0x04)
                one("serverCertificate", r.serverCertificate, 0x30)
            }
            run { Es9.parseAuthenticateClient(normal) }?.let { r ->
                txid(r.transactionId)
                one("profileMetadata", r.profileMetadata, ProfileMetadata.TAG)
                one("smdpSigned2", r.smdpSigned2, 0x30)
                one("smdpSignature2", r.smdpSignature2, 0x5F37)
                one("smdpCertificate", r.smdpCertificate, 0x30)
            }
            run { Es9.parseEventEntries(normal) }?.let { events ->
                invariant(events.size <= 16) { "too many events" }
                for (e in events) {
                    invariant(Fqdn.normalise(e.rspServerAddress) == e.rspServerAddress) { "event host not normalised" }
                    invariant(e.rspServerAddress.all { it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '.' }) { "event host not LDH" }
                    invariant(e.eventId.isNotEmpty() && e.eventId.length <= 255) { "event ID" }
                }
            }
            run { Es9.parseCancelSession(normal) }
        }
        if (bpp != null) {
            run { Es9.parseBoundProfilePackage(bpp) }?.let { (t, p) ->
                txid(t)
                invariant(p.size <= Es9.MAX_BPP_BYTES) { "package over the limit" }
                one("boundProfilePackage", p, 0xBF36)
            }
        }
    }

    private fun parse(data: ByteArray, bpp: Boolean): JsonObject? = try {
        Json.parseObject(data, if (bpp) Es9.BPP_LIMITS else Es9.LIMITS)
    } catch (e: JsonException) {
        null
    }

    private inline fun <T> run(block: () -> T): T? = try {
        block()
    } catch (e: RspException) {
        invariant(e.failure == Failure.INVALID_RESPONSE || e.failure == Failure.SERVER_REFUSED) { "unexpected failure ${e.failure}" }
        if (e.failure == Failure.SERVER_REFUSED) {
            e.subjectCode?.let { invariant(STATUS.matches(it)) { "subject code" } }
            e.reasonCode?.let { invariant(STATUS.matches(it)) { "reason code" } }
            Results.fromFailure(e)
        }
        null
    }

    private fun txid(t: ByteArray) = invariant(t.size in 1..16) { "transaction ID size" }

    private fun one(name: String, bytes: ByteArray, tag: Int) {
        val element = try {
            Tlv.one(bytes, tag)
        } catch (e: IllegalArgumentException) {
            throw Violation("$name is not one TLV")
        }
        invariant(element.tag == tag) { "$name tag" }
    }
}
