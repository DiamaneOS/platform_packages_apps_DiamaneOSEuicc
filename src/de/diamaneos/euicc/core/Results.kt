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
    const val OPERATION_EUICC_GSMA = 7

    // EuiccManager error codes
    const val ERROR_TIME_OUT = 10005
    const val ERROR_EUICC_MISSING = 10006

    // Our details, below EuiccManager's error code range
    const val DETAIL_NOT_SUPPORTED = 1
    const val DETAIL_CALLER_NOT_ALLOWED = 2
    const val DETAIL_PROFILE_NOT_FOUND = 3
    const val DETAIL_POLICY_RULES = 4
    const val DETAIL_INVALID_NICKNAME = 5
    const val DETAIL_UNKNOWN = 6

    fun error(operation: Int, detail: Int): Int = (operation shl 24) or (detail and 0xFFFFFF)

    /** Downloads and other phase-two calls. */
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
}
