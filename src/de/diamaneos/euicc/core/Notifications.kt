// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.core

import java.security.MessageDigest

/**
 * The profiles this app installed, as salted SHA-256 hashes of their ICCIDs: enough to
 * recognise their notifications, without keeping the ICCIDs. The salt is random per
 * installation and stays in the app's own storage.
 */
class OwnedSet(private val salt: ByteArray, hashes: Collection<String>) {
    private val hashes = LinkedHashSet(hashes)

    init {
        require(salt.size >= 16) { "short salt" }
    }

    val size: Int get() = hashes.size

    fun key(iccid: String): String =
        Hex.encode(MessageDigest.getInstance("SHA-256").digest(salt + iccid.toByteArray(Charsets.US_ASCII)))

    operator fun contains(iccid: String): Boolean = key(iccid) in hashes

    /** Adds [iccid]; the oldest entries go beyond [MAX]. */
    fun add(iccid: String) {
        hashes.remove(key(iccid))
        hashes.add(key(iccid))
        while (hashes.size > MAX) hashes.remove(hashes.first())
    }

    fun remove(iccid: String) {
        hashes.remove(key(iccid))
    }

    fun snapshot(): Set<String> = LinkedHashSet(hashes)

    companion object {
        const val MAX = 64
    }
}

/**
 * Sends the eUICC's pending notifications (SGP.22 3.5) for profiles this app installed, and
 * only those: each to the address in it, grouped by address, lowest sequence number first, the
 * next only after the previous one was acknowledged. Every other notification stays queued
 * until the user removes it. After a delete notification is acknowledged the profile is
 * forgotten.
 */
class NotificationFlow(
    private val card: RspCard,
    private val servers: RspServers,
    private val owned: (String) -> Boolean,
    private val forget: (String) -> Unit,
) {
    class Summary(val sent: Int, val failed: Int, val kept: Int) {
        override fun toString() = "sent=$sent failed=$failed kept=$kept"
    }

    /** One pending notification, for the list on the screen. No ICCID. */
    class Entry(val seq: Int, val event: Int, val address: String, val ours: Boolean)

    fun list(): List<Entry> = pending().map { (n, ours) -> Entry(n.metadata.seq, n.metadata.event, n.metadata.address, ours) }

    fun sendOwned(): Summary {
        val all = pending()
        val mine = all.filter { it.second }.map { it.first }
        if (mine.isEmpty()) return Summary(0, 0, all.size)
        val ciIds = EuiccInfo1.parse(card.euiccInfo1()).ciForVerification
        var sent = 0
        var failed = 0
        val groups = mine.groupBy { Fqdn.normalise(it.metadata.address) }
        for ((host, group) in groups) {
            if (host == null) {
                failed += group.size
                continue
            }
            val ordered = group.sortedBy { it.metadata.seq }
            var index = 0
            try {
                val server = servers.open(host, ServerRole.SMDP, ciIds)
                while (index < ordered.size) {
                    val n = ordered[index]
                    server.handleNotification(n.raw)
                    sent++
                    index++
                    try {
                        card.removeNotification(n.metadata.seq)
                    } catch (e: CardException) {
                        // Acknowledged; the eUICC keeps it until a later removal.
                    }
                    if (n.metadata.event == NotificationEvents.DELETE) n.metadata.iccid?.let(forget)
                }
            } catch (e: RspException) {
                failed += ordered.size - index
            }
        }
        return Summary(sent, failed, all.size - mine.size)
    }

    /** Removes one notification without sending it (the user's choice). */
    fun remove(seq: Int) = card.removeNotification(seq)

    /** Sends one notification of a profile this app installed. False if it is not one or failed. */
    fun send(seq: Int): Boolean {
        val (n, ours) = pending().firstOrNull { it.first.metadata.seq == seq } ?: return false
        if (!ours) return false
        val host = Fqdn.normalise(n.metadata.address) ?: return false
        return try {
            servers.open(host, ServerRole.SMDP, EuiccInfo1.parse(card.euiccInfo1()).ciForVerification)
                .handleNotification(n.raw)
            if (n.metadata.event == NotificationEvents.DELETE) n.metadata.iccid?.let(forget)
            try {
                card.removeNotification(seq)
            } catch (e: CardException) {
                // Acknowledged; the eUICC keeps it until a later removal.
            }
            true
        } catch (e: RspException) {
            false
        }
    }

    private fun pending(): List<Pair<PendingNotification, Boolean>> =
        card.notifications(NotificationEvents.ALL)
            .mapNotNull { PendingNotification.parseOrNull(it) }
            .map { it to (it.metadata.iccid?.let(owned) == true) }
}
