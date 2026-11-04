// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.core

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** HTTP response rules for ES9+ and ES11 (SGP.22 6.2, 6.3), apart from the connection. */
object HttpRules {
    /** Request-response functions answer 200 with JSON. Anything else fails, redirects too. */
    fun checkJsonResponse(status: Int, contentType: String?, contentLength: Long, max: Int) {
        if (status != 200) throw RspException(Failure.HTTP_STATUS)
        val type = contentType?.substringBefore(';')?.trim()
        if (!type.equals("application/json", ignoreCase = true)) throw RspException(Failure.INVALID_RESPONSE)
        if (contentLength > max) throw RspException(Failure.INVALID_RESPONSE)
    }

    /** Notifications answer 204 with an empty body (6.3). 200 is tolerated, its body ignored. */
    fun checkNotificationResponse(status: Int) {
        if (status != 204 && status != 200) throw RspException(Failure.HTTP_STATUS)
    }

    /** Reads at most [max] bytes. More is INVALID_RESPONSE. */
    fun readBounded(input: InputStream, max: Int): ByteArray {
        val out = ByteArrayOutputStream(minOf(max, 16 * 1024))
        val buffer = ByteArray(8192)
        while (true) {
            val n = input.read(buffer)
            if (n < 0) break
            if (out.size() + n > max) throw RspException(Failure.INVALID_RESPONSE)
            out.write(buffer, 0, n)
        }
        return out.toByteArray()
    }
}

/**
 * Ends one request at its overall deadline, or as soon as [stopped], by calling [abort] from
 * another thread. Per-read timeouts do not bound a server that sends one byte at a time. [abort]
 * runs on every poll until [close], because a connection still being opened can ignore it.
 */
class RequestWatch(deadlineMs: Long, stopped: () -> Boolean, abort: () -> Unit) : AutoCloseable {
    private val done = CountDownLatch(1)

    /** The request was ended here, so its failure says nothing about the server's certificate. */
    @Volatile var fired = false
        private set

    init {
        val end = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(deadlineMs)
        Thread({
            while (!done.await(POLL_MS, TimeUnit.MILLISECONDS)) {
                if (System.nanoTime() - end >= 0 || stopped()) {
                    fired = true
                    abort()
                }
            }
        }, "rsp-request-watch").apply {
            isDaemon = true
            start()
        }
    }

    override fun close() = done.countDown()

    private companion object {
        const val POLL_MS = 200L
    }
}
