// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.core

import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class RequestWatchTest {
    /** Reads from a local server that sends one byte per 20 ms for as long as it can. */
    private fun readDrip(deadlineMs: Long, stopped: () -> Boolean): RequestWatch {
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
            val sender = Thread {
                try {
                    server.accept().use { peer ->
                        while (true) {
                            peer.getOutputStream().write(1)
                            Thread.sleep(20)
                        }
                    }
                } catch (e: IOException) {
                    // The client went away.
                }
            }.apply {
                isDaemon = true
                start()
            }
            Socket(server.inetAddress, server.localPort).use { socket ->
                socket.soTimeout = 30_000
                val watch = RequestWatch(deadlineMs, stopped) { socket.close() }
                watch.use {
                    assertThrows(IOException::class.java) {
                        HttpRules.readBounded(socket.getInputStream(), 64 * 1024)
                    }
                }
                sender.join(5_000)
                return watch
            }
        }
    }

    @Test(timeout = 20_000)
    fun theDeadlineClosesASocketThatKeepsSending() {
        assertTrue(readDrip(300) { false }.fired)
    }

    @Test(timeout = 20_000)
    fun stoppingClosesItBeforeTheDeadline() {
        val stop = AtomicBoolean()
        Thread {
            Thread.sleep(300)
            stop.set(true)
        }.start()
        assertTrue(readDrip(10 * 60_000L) { stop.get() }.fired)
    }

    /** A connection still being opened ignores a disconnect, so it is asked again. */
    @Test(timeout = 20_000)
    fun abortRepeatsUntilClosed() {
        val aborts = AtomicInteger()
        RequestWatch(0, { false }) { aborts.incrementAndGet() }.use {
            while (aborts.get() < 2) Thread.sleep(50)
        }
    }

    @Test(timeout = 20_000)
    fun aRequestThatEndsInTimeIsLeftAlone() {
        val aborts = AtomicInteger()
        val watch = RequestWatch(60_000, { false }) { aborts.incrementAndGet() }
        watch.close()
        Thread.sleep(500)
        assertFalse(watch.fired)
        assertTrue(aborts.get() == 0)
    }
}
