// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.core

/**
 * Result codes. The constants mirror EuiccService, EuiccCardManager and EuiccManager (system
 * API) so this file runs in host tests without Android.
 *
 * An error is (operation << 24) | detail: EuiccController unpacks that into
 * EuiccManager.EXTRA_EMBEDDED_SUBSCRIPTION_OPERATION_CODE and _ERROR_CODE for the caller.
 */
object Results {
    // EuiccService
    const val OK = 0
    const val MUST_DEACTIVATE_SIM = -1

    // EuiccCardManager. Positive codes are the eUICC's own SGP.22 error codes.
    const val CARD_OK = 0
    const val CARD_UNKNOWN_ERROR = -1
    const val CARD_EUICC_NOT_FOUND = -2
    const val CARD_CALLER_NOT_ALLOWED = -3
    const val CARD_PROFILE_DOES_NOT_EXIST = -4

    /** Ours: the card call did not answer in time. */
    const val CARD_TIMEOUT = Int.MIN_VALUE

    // EuiccManager operation codes
    const val OPERATION_SYSTEM = 1
    const val OPERATION_EUICC_CARD = 3
    const val OPERATION_SWITCH = 4
    const val OPERATION_DOWNLOAD = 5
    const val OPERATION_EUICC_GSMA = 7
    const val OPERATION_SMDX_SUBJECT_REASON_CODE = 10
    const val OPERATION_HTTP = 11

    // EuiccManager error codes
    const val ERROR_INVALID_ACTIVATION_CODE = 10001
    const val ERROR_INVALID_CONFIRMATION_CODE = 10002
    const val ERROR_TIME_OUT = 10005
    const val ERROR_EUICC_MISSING = 10006
    const val ERROR_INSTALL_PROFILE = 10009
    const val ERROR_DISALLOWED_BY_PPR = 10010
    const val ERROR_CERTIFICATE_ERROR = 10012
    const val ERROR_CONNECTION_ERROR = 10014
    const val ERROR_INVALID_RESPONSE = 10015
    const val ERROR_OPERATION_BUSY = 10016

    // Our details, below EuiccManager's error code range
    const val DETAIL_NOT_SUPPORTED = 1
    const val DETAIL_CALLER_NOT_ALLOWED = 2
    const val DETAIL_PROFILE_NOT_FOUND = 3
    const val DETAIL_POLICY_RULES = 4
    const val DETAIL_INVALID_NICKNAME = 5
    const val DETAIL_UNKNOWN = 6
    const val DETAIL_CANCELLED = 7
    const val DETAIL_NOT_CONSENTED = 8

    fun error(operation: Int, detail: Int): Int = (operation shl 24) or (detail and 0xFFFFFF)

    /** Calls this LPA does not serve: metadata lookups and the default download list. */
    val NOT_SUPPORTED = error(OPERATION_SYSTEM, DETAIL_NOT_SUPPORTED)
    val EUICC_MISSING = error(OPERATION_SYSTEM, ERROR_EUICC_MISSING)
    val INVALID_NICKNAME = error(OPERATION_EUICC_CARD, DETAIL_INVALID_NICKNAME)

    /** The EuiccService result for an EuiccCardManager result. */
    fun fromCard(code: Int): Int = when {
        code == CARD_OK -> OK
        code == CARD_TIMEOUT -> error(OPERATION_SYSTEM, ERROR_TIME_OUT)
        code > 0 -> error(OPERATION_EUICC_GSMA, code)
        code == CARD_EUICC_NOT_FOUND -> EUICC_MISSING
        code == CARD_CALLER_NOT_ALLOWED -> error(OPERATION_SYSTEM, DETAIL_CALLER_NOT_ALLOWED)
        code == CARD_PROFILE_DOES_NOT_EXIST -> error(OPERATION_EUICC_CARD, DETAIL_PROFILE_NOT_FOUND)
        else -> error(OPERATION_EUICC_CARD, DETAIL_UNKNOWN)
    }

    /**
     * Whether a card call may succeed if repeated shortly: the card is away (it restarts after
     * a profile change) or the call failed without an answer from the card.
     */
    fun isTransient(code: Int): Boolean =
        code == CARD_EUICC_NOT_FOUND || code == CARD_UNKNOWN_ERROR || code == CARD_TIMEOUT

    /** The EuiccService result for a download outcome; EuiccController passes it to the caller. */
    fun fromOutcome(outcome: Outcome): Int = when (outcome) {
        is Outcome.Installed, is Outcome.Checked, is Outcome.Found -> OK
        Outcome.Cancelled -> error(OPERATION_DOWNLOAD, DETAIL_CANCELLED)
        is Outcome.Failed -> fromFailure(outcome.error)
    }

    fun fromFailure(e: RspException): Int = when (e.failure) {
        Failure.EUICC_MISSING -> EUICC_MISSING
        Failure.NO_TRUSTED_CI, Failure.TLS -> error(OPERATION_HTTP, ERROR_CERTIFICATE_ERROR)
        Failure.CARD, Failure.CARD_REFUSED_SERVER ->
            e.cardCode?.let { fromCard(it) } ?: error(OPERATION_EUICC_CARD, DETAIL_UNKNOWN)
        Failure.NETWORK -> error(OPERATION_HTTP, ERROR_CONNECTION_ERROR)
        Failure.HTTP_STATUS, Failure.INVALID_RESPONSE, Failure.SERVER_MISMATCH, Failure.OID_MISMATCH ->
            error(OPERATION_DOWNLOAD, ERROR_INVALID_RESPONSE)
        Failure.SERVER_REFUSED -> smdxCode(e.subjectCode, e.reasonCode) ?: error(OPERATION_DOWNLOAD, DETAIL_UNKNOWN)
        Failure.CONFIRMATION_CODE_MISSING -> error(OPERATION_DOWNLOAD, ERROR_INVALID_CONFIRMATION_CODE)
        Failure.PPR_NOT_ALLOWED -> error(OPERATION_DOWNLOAD, ERROR_DISALLOWED_BY_PPR)
        Failure.INSTALL_FAILED -> error(OPERATION_DOWNLOAD, ERROR_INSTALL_PROFILE)
        Failure.USER_TIMEOUT -> error(OPERATION_DOWNLOAD, ERROR_TIME_OUT)
        Failure.BUSY -> error(OPERATION_DOWNLOAD, ERROR_OPERATION_BUSY)
        Failure.NOT_CONSENTED -> error(OPERATION_DOWNLOAD, DETAIL_NOT_CONSENTED)
        Failure.FRAMEWORK -> error(OPERATION_SYSTEM, DETAIL_UNKNOWN)
    }

    /**
     * An SM-DP+ subject and reason code (SGP.22 5.2.6) in EuiccManager's
     * OPERATION_SMDX_SUBJECT_REASON_CODE form: six nibbles, three per code. Null if a code has
     * more than three parts or a part above 15.
     */
    fun smdxCode(subject: String?, reason: String?): Int? {
        fun nibbles(code: String?): List<Int>? {
            val parts = code?.split('.')?.map { it.toIntOrNull() ?: return null } ?: return null
            if (parts.isEmpty() || parts.size > 3 || parts.any { it !in 0..15 }) return null
            return List(3 - parts.size) { 0 } + parts
        }
        val all = (nibbles(subject) ?: return null) + (nibbles(reason) ?: return null)
        return error(OPERATION_SMDX_SUBJECT_REASON_CODE, all.fold(0) { acc, n -> (acc shl 4) or n })
    }
}
