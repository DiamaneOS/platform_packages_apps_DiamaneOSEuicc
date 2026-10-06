// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.core

import java.io.ByteArrayOutputStream
import java.io.InputStream

/** HTTP response rules for ES9+ and ES11 (SGP.22 6.2, 6.3), apart from the connection. */
object HttpRules {
    /** Request-response functions answer 200 with JSON; anything else fails, redirects too. */
    fun checkJsonResponse(status: Int, contentType: String?, contentLength: Long, max: Int) {
        if (status != 200) throw RspException(Failure.HTTP_STATUS)
        val type = contentType?.substringBefore(';')?.trim()
        if (!type.equals("application/json", ignoreCase = true)) throw RspException(Failure.INVALID_RESPONSE)
        if (contentLength > max) throw RspException(Failure.INVALID_RESPONSE)
    }

    /** Notifications answer 204 with an empty body (6.3); 200 is tolerated, its body ignored. */
    fun checkNotificationResponse(status: Int) {
        if (status != 204 && status != 200) throw RspException(Failure.HTTP_STATUS)
    }

    /** Reads at most [max] bytes; more is INVALID_RESPONSE. */
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
