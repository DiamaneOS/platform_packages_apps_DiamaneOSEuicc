// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.core

import java.util.Base64

/** Why an RSP operation stopped. Shown to the user as text; logged as the name only. */
enum class Failure {
    /** No eUICC in the slot, or it went away. */
    EUICC_MISSING,

    /** The eUICC trusts no GSMA CI this app ships, so no server can be authenticated. */
    NO_TRUSTED_CI,

    /** The eUICC returned an error for a card command ([RspException.cardCode]). */
    CARD,

    /** The eUICC refused the server in AuthenticateServer ([RspException.cardCode]). */
    CARD_REFUSED_SERVER,

    /** No connection, a timeout or a broken stream. */
    NETWORK,

    /** The server's TLS certificate failed the SGP.22 checks; nothing was sent. */
    TLS,

    /** An HTTP status other than the one the function uses (redirects included). */
    HTTP_STATUS,

    /** A response that is not the expected JSON, base64 or ASN.1, or too large. */
    INVALID_RESPONSE,

    /** The server's function failed ([RspException.subjectCode], [RspException.reasonCode]). */
    SERVER_REFUSED,

    /** The server's signed data does not match this session or this code. */
    SERVER_MISMATCH,

    /** The code names an SM-DP+ OID that the server's certificate does not carry. */
    OID_MISMATCH,

    /** A confirmation code is required and none was given. */
    CONFIRMATION_CODE_MISSING,

    /** The profile's policy rules are not allowed on this eUICC or with the installed profiles. */
    PPR_NOT_ALLOWED,

    /** The eUICC could not install the profile ([RspException.cardCode] or the install result). */
    INSTALL_FAILED,

    /** The user did not answer in time. */
    USER_TIMEOUT,

    /** Another download, check or search is running. */
    BUSY,

    /** The request did not come from this app's own screen. */
    NOT_CONSENTED,

    /** Android's eUICC service refused or lost the download before this app ran it. */
    FRAMEWORK,
}

/** An RSP step failed. The message is the [Failure] name only. */
class RspException(
    val failure: Failure,
    val cardCode: Int? = null,
    val subjectCode: String? = null,
    val reasonCode: String? = null,
    cause: Throwable? = null,
) : Exception(failure.name, cause)

/**
 * ES9+ and ES11 over HTTPS with the JSON binding (SGP.22 v2.5 sections 5.6, 5.8, 6.1 and 6.5):
 * request bodies and strict response parsing. Binary fields are base64; transaction IDs are
 * hexadecimal.
 */
object Es9 {
    const val USER_AGENT = "gsma-rsp-lpad"

    /** The highest SGP.22 version this LPA follows (6.1). */
    const val ADMIN_PROTOCOL = "gsma/rsp/v2.2.0"

    // 6.5.2: ES11 uses the ES9+ paths.
    const val PATH_INITIATE_AUTHENTICATION = "/gsma/rsp2/es9plus/initiateAuthentication"
    const val PATH_AUTHENTICATE_CLIENT = "/gsma/rsp2/es9plus/authenticateClient"
    const val PATH_GET_BOUND_PROFILE_PACKAGE = "/gsma/rsp2/es9plus/getBoundProfilePackage"
    const val PATH_HANDLE_NOTIFICATION = "/gsma/rsp2/es9plus/handleNotification"
    const val PATH_CANCEL_SESSION = "/gsma/rsp2/es9plus/cancelSession"

    /** Largest response body accepted, except GetBoundProfilePackage. */
    const val MAX_RESPONSE_BYTES = 64 * 1024

    /** Largest GetBoundProfilePackage response: base64 of a package up to about 1.5 MB. */
    const val MAX_BPP_RESPONSE_BYTES = 2 * 1024 * 1024

    /** Largest Bound Profile Package accepted. */
    const val MAX_BPP_BYTES = 1536 * 1024

    val LIMITS = JsonLimits(maxDepth = 6, maxStringChars = MAX_RESPONSE_BYTES, maxMembers = 32, maxItems = 32)
    val BPP_LIMITS = JsonLimits(maxDepth = 6, maxStringChars = MAX_BPP_RESPONSE_BYTES, maxMembers = 32, maxItems = 32)

    private val STATUS_CODE = Regex("[0-9]{1,3}(\\.[0-9]{1,3}){0,5}")
    private val TRANSACTION_ID = Regex("[0-9A-Fa-f]{2,32}")

    class InitiateAuthentication(
        val transactionId: ByteArray,
        val serverSigned1: ByteArray,
        val serverSignature1: ByteArray,
        val euiccCiPkIdToBeUsed: ByteArray,
        val serverCertificate: ByteArray,
    ) {
        override fun toString() = "InitiateAuthentication"
    }

    class AuthenticateClient(
        val transactionId: ByteArray,
        val profileMetadata: ByteArray,
        val smdpSigned2: ByteArray,
        val smdpSignature2: ByteArray,
        val smdpCertificate: ByteArray,
    ) {
        override fun toString() = "AuthenticateClient"
    }

    /** An SM-DS event (5.8.2): where a profile waits for this eUICC, and its EventID. */
    class EventEntry(val eventId: String, val rspServerAddress: String) {
        override fun toString() = "EventEntry"
    }

    // Requests (6.5.2.x). ES9+ and ES11 requests carry no JSON header.

    fun initiateAuthenticationRequest(challenge: ByteArray, euiccInfo1: ByteArray, address: String) =
        Json.write(mapOf("euiccChallenge" to b64(challenge), "euiccInfo1" to b64(euiccInfo1), "smdpAddress" to address))

    fun authenticateClientRequest(transactionId: ByteArray, authenticateServerResponse: ByteArray) =
        Json.write(mapOf("transactionId" to hex(transactionId), "authenticateServerResponse" to b64(authenticateServerResponse)))

    fun getBoundProfilePackageRequest(transactionId: ByteArray, prepareDownloadResponse: ByteArray) =
        Json.write(mapOf("transactionId" to hex(transactionId), "prepareDownloadResponse" to b64(prepareDownloadResponse)))

    fun handleNotificationRequest(pendingNotification: ByteArray) =
        Json.write(mapOf("pendingNotification" to b64(pendingNotification)))

    fun cancelSessionRequest(transactionId: ByteArray, cancelSessionResponse: ByteArray) =
        Json.write(mapOf("transactionId" to hex(transactionId), "cancelSessionResponse" to b64(cancelSessionResponse)))

    // Responses. Every parser first checks the function execution status.

    fun parseInitiateAuthentication(body: JsonObject): InitiateAuthentication {
        checkStatus(body)
        return InitiateAuthentication(
            transactionId = transactionId(body),
            serverSigned1 = tlv(body, "serverSigned1", 0x30),
            serverSignature1 = tlv(body, "serverSignature1", 0x5F37),
            // The schema's name; SGP.22 Annex I spells it "euiccCiPKIdTobeUsed".
            euiccCiPkIdToBeUsed = tlv(body, if (body.members.containsKey("euiccCiPKIdToBeUsed")) "euiccCiPKIdToBeUsed" else "euiccCiPKIdTobeUsed", 0x04),
            serverCertificate = tlv(body, "serverCertificate", 0x30),
        )
    }

    fun parseAuthenticateClient(body: JsonObject): AuthenticateClient {
        checkStatus(body)
        return AuthenticateClient(
            transactionId = transactionId(body),
            profileMetadata = tlv(body, "profileMetadata", ProfileMetadata.TAG),
            smdpSigned2 = tlv(body, "smdpSigned2", 0x30),
            smdpSignature2 = tlv(body, "smdpSignature2", 0x5F37),
            smdpCertificate = tlv(body, "smdpCertificate", 0x30),
        )
    }

    /** Transaction ID and the Bound Profile Package. */
    fun parseBoundProfilePackage(body: JsonObject): Pair<ByteArray, ByteArray> {
        checkStatus(body)
        val bpp = tlv(body, "boundProfilePackage", 0xBF36)
        if (bpp.size > MAX_BPP_BYTES) throw invalid()
        return transactionId(body) to bpp
    }

    fun parseCancelSession(body: JsonObject) = checkStatus(body)

    /** ES11.AuthenticateClient (5.8.2, 6.5.2): the valid events only, at most 16. */
    fun parseEventEntries(body: JsonObject): List<EventEntry> {
        checkStatus(body)
        transactionId(body)
        val entries = body.array("eventEntries") ?: throw invalid()
        return entries.items.mapNotNull { item ->
            val entry = item as? JsonObject ?: return@mapNotNull null
            val id = entry.string("eventId") ?: return@mapNotNull null
            val address = entry.string("rspServerAddress") ?: return@mapNotNull null
            ActivationCode.fromEvent(address, id)?.let { EventEntry(it.matchingId, it.smdpAddress) }
        }.take(16)
    }

    /**
     * The JSON response header (6.5.1.4): Executed-Success or Executed-WithWarning go on;
     * Failed and Expired throw SERVER_REFUSED with the status codes if they are well formed.
     * The server's "message" text is never read.
     */
    fun checkStatus(body: JsonObject) {
        val status = body.obj("header")?.obj("functionExecutionStatus") ?: throw invalid()
        when (status.string("status")) {
            "Executed-Success", "Executed-WithWarning" -> return
            "Failed", "Expired" -> {
                val data = status.obj("statusCodeData")
                throw RspException(
                    Failure.SERVER_REFUSED,
                    subjectCode = data?.string("subjectCode")?.takeIf { STATUS_CODE.matches(it) },
                    reasonCode = data?.string("reasonCode")?.takeIf { STATUS_CODE.matches(it) },
                )
            }
            else -> throw invalid()
        }
    }

    fun b64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)

    /** Uppercase hexadecimal, as the JSON schema's pattern expects. */
    fun hex(bytes: ByteArray): String = Hex.encode(bytes).uppercase(java.util.Locale.ROOT)

    private fun transactionId(body: JsonObject): ByteArray {
        val text = body.string("transactionId") ?: throw invalid()
        if (!TRANSACTION_ID.matches(text)) throw invalid()
        return Hex.decode(text) ?: throw invalid()
    }

    /** A base64 member that must decode to exactly one TLV with [tag] (strict base64, RFC 4648). */
    private fun tlv(body: JsonObject, name: String, tag: Int): ByteArray {
        val text = body.string(name) ?: throw invalid()
        val bytes = try {
            Base64.getDecoder().decode(text)
        } catch (e: IllegalArgumentException) {
            throw invalid()
        }
        try {
            Tlv.one(bytes, tag)
        } catch (e: IllegalArgumentException) {
            throw invalid()
        }
        return bytes
    }

    private fun invalid() = RspException(Failure.INVALID_RESPONSE)
}
