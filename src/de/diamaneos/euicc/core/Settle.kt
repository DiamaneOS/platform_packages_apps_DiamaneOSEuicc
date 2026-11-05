// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.core

/**
 * Reads until [settled] holds, at most [attempts] times with [pause] milliseconds between tries.
 * The eUICC restarts after a profile switch and fails reads for a few seconds.
 */
fun <T> readUntilSettled(
    attempts: Int,
    pause: Long,
    sleep: (Long) -> Unit = { Thread.sleep(it) },
    read: () -> T,
    settled: (T) -> Boolean,
): T {
    require(attempts >= 1)
    var value = read()
    repeat(attempts - 1) {
        if (settled(value)) return value
        sleep(pause)
        value = read()
    }
    return value
}

/**
 * Runs [block], and again after each pause in [pauses] (milliseconds) while it fails with a
 * transient [CardException]: right after a switch the slot can still show the eUICC while it
 * restarts and refuses commands. [retrying] hears each such failure. Other failures, and the
 * last one, are thrown.
 */
fun <T> retryWhileRestarting(
    pauses: List<Long>,
    sleep: (Long) -> Unit = { Thread.sleep(it) },
    retrying: (CardException) -> Unit = {},
    block: () -> T,
): T {
    for (pause in pauses) {
        try {
            return block()
        } catch (e: CardException) {
            if (!Results.isTransient(e.code)) throw e
            retrying(e)
        }
        sleep(pause)
    }
    return block()
}
