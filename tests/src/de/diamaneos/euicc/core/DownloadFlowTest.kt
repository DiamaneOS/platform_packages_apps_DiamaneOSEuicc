// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** A scripted eUICC: records the commands; [fail] makes one throw a CardException. */
class FakeCard : RspCard {
    val calls = mutableListOf<String>()
    var info1 = Rsp.euiccInfo1()
    var authenticateResponse = Rsp.authenticateServerOk()
    var fail = mutableMapOf<String, Int>()
    var hashCc: ByteArray? = null
    var matchingId: String? = null
    var cancelReasons = mutableListOf<Int>()
    val pending = mutableListOf<ByteArray>()
    var installAs: ByteArray? = Rsp.installResult()
    var operational = false
    var ppr = PprCheck.ALLOWED

    private fun call(name: String) {
        calls += name
        fail[name]?.let { throw CardException(it) }
    }

    override fun euiccInfo1() = info1.also { call("info1") }
    override fun euiccChallenge() = Rsp.CHALLENGE.also { call("challenge") }
    override fun authenticateServer(matchingId: String, auth: Es9.InitiateAuthentication): ByteArray {
        call("authenticateServer")
        this.matchingId = matchingId
        return authenticateResponse
    }
    override fun prepareDownload(hashCc: ByteArray?, client: Es9.AuthenticateClient): ByteArray {
        call("prepareDownload")
        this.hashCc = hashCc
        return Rsp.prepareDownloadOk()
    }
    override fun loadBoundProfilePackage(bpp: ByteArray): ByteArray {
        installAs?.let { pending += it }
        call("load")
        return installAs ?: throw CardException(-1)
    }
    override fun cancelSession(transactionId: ByteArray, reason: Int): ByteArray {
        call("cancel")
        cancelReasons += reason
        return Rsp.cancelSessionOk()
    }
    override fun notifications(events: Int): List<ByteArray> {
        call("notifications")
        return pending.filter { PendingNotification.parseOrNull(it)?.metadata?.event?.and(events) != 0 }
    }
    override fun removeNotification(seq: Int) {
        call("remove $seq")
        pending.removeAll { PendingNotification.parseOrNull(it)?.metadata?.seq == seq }
    }
    override fun hasOperationalProfile() = operational
    override fun pprCheck(rules: Int, owner: OperatorId?) = ppr
}

/** A scripted RSP server. [refuse] makes a function fail with SERVER_REFUSED, [drop] with NETWORK. */
class FakeServer(private val host: String = "smdp.example.com") : RspServer {
    val calls = mutableListOf<String>()
    var initiate = Rsp.initiateAuthentication()
    var client = Rsp.authenticateClient()
    var bpp = Rsp.boundProfilePackage()
    var events = listOf(Es9.EventEntry("EVENT-1", "smdp.example.com"))
    val refuse = mutableSetOf<String>()
    val drop = mutableSetOf<String>()
    val notified = mutableListOf<ByteArray>()

    private fun call(name: String) {
        calls += name
        if (name in refuse) throw RspException(Failure.SERVER_REFUSED, subjectCode = "8.2.6", reasonCode = "3.8")
        if (name in drop) throw RspException(Failure.NETWORK)
    }

    override fun initiateAuthentication(challenge: ByteArray, euiccInfo1: ByteArray) = initiate.also { call("initiate") }
    override fun authenticateClient(transactionId: ByteArray, authenticateServerResponse: ByteArray) = client.also { call("authenticateClient") }
    override fun authenticateClientEs11(transactionId: ByteArray, authenticateServerResponse: ByteArray) = events.also { call("authenticateClientEs11") }
    override fun getBoundProfilePackage(transactionId: ByteArray, prepareDownloadResponse: ByteArray): Pair<ByteArray, ByteArray> {
        call("getBpp")
        return Rsp.TRANSACTION_ID to bpp
    }
    override fun handleNotification(pendingNotification: ByteArray) {
        call("handleNotification")
        notified += pendingNotification
    }
    override fun cancelSession(transactionId: ByteArray, cancelSessionResponse: ByteArray) = call("cancelSession")
}

class FakeServers(vararg servers: Pair<String, FakeServer>) : RspServers {
    val byHost = servers.toMap().toMutableMap()
    val opened = mutableListOf<String>()
    var noCi = false

    override fun open(host: String, role: ServerRole, euiccCiIds: List<ByteArray>): RspServer {
        if (noCi || euiccCiIds.none { it.contentEquals(Rsp.CI1) }) throw RspException(Failure.NO_TRUSTED_CI)
        opened += "$host/$role"
        return byHost[host] ?: throw RspException(Failure.NETWORK)
    }
}

/** Answers the confirmation with [answer] (null: no answer in time). */
class FakeUser(var answer: Confirmation? = Confirmation.Accept(null), var cancelAt: Step? = null) : RspUser {
    val steps = mutableListOf<Step>()
    var request: ConfirmRequest? = null
    override var cancelled = false
    override fun step(step: Step) {
        steps += step
        if (step == cancelAt) cancelled = true
    }
    override fun confirm(request: ConfirmRequest): Confirmation? {
        this.request = request
        return answer
    }
}

class DownloadFlowTest {
    private val card = FakeCard()
    private val server = FakeServer()
    private val servers = FakeServers("smdp.example.com" to server)
    private val user = FakeUser()
    private val owned = mutableListOf<String>()
    private val flow = DownloadFlow(card, servers, user) { owned += it }
    private val code = ActivationCode.parse("LPA:1\$smdp.example.com\$MATCHING-1")

    private fun failure(outcome: Outcome) = (outcome as Outcome.Failed).failure

    @Test
    fun downloadsInstallsAndNotifies() {
        val outcome = flow.download(code)
        assertTrue(outcome.toString(), outcome is Outcome.Installed)
        assertTrue((outcome as Outcome.Installed).notified)
        assertEquals("MATCHING-1", card.matchingId)
        assertEquals(listOf("initiate", "authenticateClient", "getBpp", "handleNotification"), server.calls)
        assertEquals(listOf("info1", "challenge", "authenticateServer", "prepareDownload", "load", "notifications", "remove 7"), card.calls)
        assertNull(card.hashCc)
        assertEquals(listOf(ICCID_A), owned)
        assertTrue(card.pending.isEmpty())
        assertEquals("Travel 5 GB", user.request!!.metadata.profileName)
        assertFalse(user.request!!.confirmationCodeRequired)
        assertEquals(Step.NOTIFYING, user.steps.last())
    }

    /** The code's own flag or the server's smdpSigned2 asks for a confirmation code (3.1.3). */
    @Test
    fun hashesTheConfirmationCode() {
        server.client = Rsp.authenticateClient(signed2 = Rsp.smdpSigned2(ccRequired = true))
        user.answer = Confirmation.Accept(" 1234 ")
        assertTrue(flow.download(code) is Outcome.Installed)
        assertTrue(user.request!!.confirmationCodeRequired)
        assertArrayEquals(ConfirmationCode.hash("1234", Rsp.TRANSACTION_ID), card.hashCc)

        val flagged = FakeCard()
        val user2 = FakeUser(Confirmation.Accept("5678"))
        DownloadFlow(flagged, FakeServers("smdp.example.com" to FakeServer()), user2)
            .download(ActivationCode.parse("1\$smdp.example.com\$M\$\$1"))
        assertArrayEquals(ConfirmationCode.hash("5678", Rsp.TRANSACTION_ID), flagged.hashCc)
    }

    @Test
    fun missingConfirmationCodeCancelsPostponed() {
        server.client = Rsp.authenticateClient(signed2 = Rsp.smdpSigned2(ccRequired = true))
        user.answer = Confirmation.Accept("  ")
        assertEquals(Failure.CONFIRMATION_CODE_MISSING, failure(flow.download(code)))
        assertEquals(listOf(CancelReason.POSTPONED), card.cancelReasons)
        assertEquals(listOf("initiate", "authenticateClient", "cancelSession"), server.calls)
        assertFalse("prepareDownload" in card.calls)
    }

    /** Dry run: the server never gets AuthenticateClient, so never sees the MatchingID. */
    @Test
    fun dryRunStopsBeforeTheMatchingIdLeaves() {
        val outcome = flow.check(code)
        assertTrue(outcome is Outcome.Checked)
        assertEquals("GSMA RSP2 Root CI1", (outcome as Outcome.Checked).serverCi)
        assertEquals("", card.matchingId)
        assertEquals(listOf("initiate"), server.calls)
        assertEquals(listOf(CancelReason.POSTPONED), card.cancelReasons)
        assertTrue(owned.isEmpty())
    }

    @Test
    fun cancelBeforeAuthenticateClientTouchesOnlyTheCard() {
        user.cancelAt = Step.CONNECTING
        assertEquals(Outcome.Cancelled, flow.download(code))
        assertEquals(listOf("initiate"), server.calls)
        // Cancelled before AuthenticateServer: nothing to cancel on the eUICC either.
        assertFalse("authenticateServer" in card.calls)

        val card2 = FakeCard()
        val server2 = FakeServer()
        val user2 = FakeUser(cancelAt = Step.AUTHENTICATING)
        assertEquals(Outcome.Cancelled, DownloadFlow(card2, FakeServers("smdp.example.com" to server2), user2).download(code))
        // Cancelled after AuthenticateClient: the server learns it, as "postponed".
        assertEquals(listOf("initiate", "authenticateClient", "cancelSession"), server2.calls)
        assertEquals(listOf(CancelReason.POSTPONED), card2.cancelReasons)
    }

    @Test
    fun notNowAndNoAnswerKeepTheOrder() {
        user.answer = Confirmation.Decline
        assertEquals(Outcome.Cancelled, flow.download(code))
        assertEquals(listOf(CancelReason.POSTPONED), card.cancelReasons)
        assertEquals("cancelSession", server.calls.last())

        val card2 = FakeCard()
        val outcome = DownloadFlow(card2, FakeServers("smdp.example.com" to FakeServer()), FakeUser(answer = null)).download(code)
        assertEquals(Failure.USER_TIMEOUT, failure(outcome))
        assertEquals(listOf(CancelReason.TIMEOUT), card2.cancelReasons)
    }

    @Test
    fun cancelAfterThePackageDownloadIsTooLate() {
        user.cancelAt = Step.DOWNLOADING
        assertTrue(flow.download(code) is Outcome.Installed)
    }

    @Test
    fun serverAndCardChecksStopBeforeTheMatchingIdLeaves() {
        for ((change, expected) in listOf<Pair<(FakeServer) -> Unit, Failure>>(
            { s: FakeServer -> s.initiate = Rsp.initiateAuthentication(Rsp.serverSigned1(address = "evil.example.com")) } to Failure.SERVER_MISMATCH,
            { s: FakeServer -> s.initiate = Rsp.initiateAuthentication(Rsp.serverSigned1(challenge = ByteArray(16))) } to Failure.SERVER_MISMATCH,
            { s: FakeServer -> s.initiate = Rsp.initiateAuthentication(Rsp.serverSigned1(transactionId = ByteArray(16))) } to Failure.SERVER_MISMATCH,
            { s: FakeServer -> s.initiate = Rsp.initiateAuthentication(ciToBeUsed = Rsp.TEST_CI) } to Failure.SERVER_MISMATCH,
            { s: FakeServer -> s.initiate = Rsp.initiateAuthentication(Der.tlv(0x30, byteArrayOf(1))) } to Failure.INVALID_RESPONSE,
            { s: FakeServer -> s.drop += "initiate" } to Failure.NETWORK,
            { s: FakeServer -> s.refuse += "initiate" } to Failure.SERVER_REFUSED,
        )) {
            val card = FakeCard()
            val server = FakeServer().also(change)
            val outcome = DownloadFlow(card, FakeServers("smdp.example.com" to server), FakeUser()).download(code)
            assertEquals(expected, failure(outcome))
            assertFalse("authenticateServer" in card.calls)
            assertFalse("authenticateClient" in server.calls)
        }
    }

    @Test
    fun oidFromTheCodeMustMatchTheServerCertificate() {
        server.initiate = Rsp.initiateAuthentication(certificate = Certificates.parse(
            java.util.Base64.getMimeDecoder().decode(TlsFixtures.LEAF_DP.lines().filter { !it.startsWith("-----") }.joinToString(""))).encoded)
        val match = flow.check(ActivationCode.parse("1\$smdp.example.com\$M\$1.3.6.1.4.1.99999.1"))
        assertTrue(match.toString(), match is Outcome.Checked)
        val other = flow.check(ActivationCode.parse("1\$smdp.example.com\$M\$1.3.6.1.4.1.99999.2"))
        assertEquals(Failure.OID_MISMATCH, failure(other))
    }

    @Test
    fun eUiccRefusalsAndMissingTrust() {
        card.fail["authenticateServer"] = 2 // invalidSignature
        val refused = flow.download(code) as Outcome.Failed
        assertEquals(Failure.CARD_REFUSED_SERVER, refused.failure)
        assertEquals(2, refused.error.cardCode)
        assertEquals(listOf("initiate"), server.calls)

        servers.noCi = true
        assertEquals(Failure.NO_TRUSTED_CI, failure(DownloadFlow(FakeCard(), servers, FakeUser()).download(code)))

        val card2 = FakeCard().apply { authenticateResponse = Rsp.authenticateServerOk(ByteArray(16)) }
        val server2 = FakeServer()
        assertEquals(Failure.CARD_REFUSED_SERVER, failure(DownloadFlow(card2, FakeServers("smdp.example.com" to server2), FakeUser()).download(code)))
        assertEquals(listOf("initiate"), server2.calls)
    }

    @Test
    fun authenticateClientFailures() {
        server.refuse += "authenticateClient"
        val outcome = flow.download(code) as Outcome.Failed
        assertEquals(Failure.SERVER_REFUSED, outcome.failure)
        assertEquals("8.2.6", outcome.error.subjectCode)
        // The server ended its session: only the eUICC's is cancelled.
        assertEquals(listOf("initiate", "authenticateClient"), server.calls)
        assertEquals(listOf(CancelReason.POSTPONED), card.cancelReasons)

        val server2 = FakeServer().apply { drop += "authenticateClient" }
        val card2 = FakeCard()
        DownloadFlow(card2, FakeServers("smdp.example.com" to server2), FakeUser()).download(code)
        assertEquals(listOf("initiate", "authenticateClient", "cancelSession"), server2.calls)

        val server3 = FakeServer().apply { client = Rsp.authenticateClient(signed2 = Rsp.smdpSigned2(transactionId = ByteArray(16))) }
        assertEquals(Failure.SERVER_MISMATCH, failure(DownloadFlow(FakeCard(), FakeServers("smdp.example.com" to server3), FakeUser()).download(code)))
    }

    @Test
    fun profilePolicyRules() {
        server.client = Rsp.authenticateClient(metadata = Rsp.metadata(ppr = intArrayOf(1), owner = true))
        card.operational = true
        assertEquals(Failure.PPR_NOT_ALLOWED, failure(flow.download(code)))
        assertEquals(listOf(CancelReason.POSTPONED), card.cancelReasons)

        val card2 = FakeCard().apply { ppr = PprCheck.FORBIDDEN }
        val server2 = FakeServer().apply { client = Rsp.authenticateClient(metadata = Rsp.metadata(ppr = intArrayOf(2))) }
        assertEquals(Failure.PPR_NOT_ALLOWED, failure(DownloadFlow(card2, FakeServers("smdp.example.com" to server2), FakeUser()).download(code)))

        val card3 = FakeCard().apply { ppr = PprCheck.CONSENT_REQUIRED }
        val server3 = FakeServer().apply {
            client = Rsp.authenticateClient(metadata = Rsp.metadata(ppr = intArrayOf(2)))
            bpp = Rsp.boundProfilePackage(Rsp.metadata(ppr = intArrayOf(2)))
        }
        val user3 = FakeUser()
        assertTrue(DownloadFlow(card3, FakeServers("smdp.example.com" to server3), user3).download(code) is Outcome.Installed)
        assertTrue(user3.request!!.pprConsentRequired)

        // The package's rules differ from the ones the user agreed to (3.1.3.2).
        val card4 = FakeCard()
        val server4 = FakeServer().apply { bpp = Rsp.boundProfilePackage(Rsp.metadata(ppr = intArrayOf(2))) }
        assertEquals(Failure.PPR_NOT_ALLOWED, failure(DownloadFlow(card4, FakeServers("smdp.example.com" to server4), FakeUser()).download(code)))
        assertFalse("load" in card4.calls)
    }

    @Test
    fun packageDownloadAndInstallFailures() {
        // A wrong confirmation code is refused at GetBoundProfilePackage: the session is over.
        server.refuse += "getBpp"
        assertEquals(Failure.SERVER_REFUSED, failure(flow.download(code)))
        assertEquals(listOf("initiate", "authenticateClient", "getBpp"), server.calls)

        // The eUICC rejected the package: its install result still goes to the server.
        val card2 = FakeCard().apply { installAs = Rsp.installResult(errorReason = 10) }
        val server2 = FakeServer()
        val owned2 = mutableListOf<String>()
        val failed = DownloadFlow(card2, FakeServers("smdp.example.com" to server2), FakeUser()) { owned2 += it }.download(code) as Outcome.Failed
        assertEquals(Failure.INSTALL_FAILED, failed.failure)
        assertEquals(10, failed.error.cardCode)
        assertEquals("handleNotification", server2.calls.last())
        assertTrue(owned2.isEmpty())

        // Nothing reached the eUICC: no install result, so the session is cancelled.
        val card3 = FakeCard().apply { installAs = null }
        val server3 = FakeServer()
        assertEquals(Failure.INSTALL_FAILED, failure(DownloadFlow(card3, FakeServers("smdp.example.com" to server3), FakeUser()).download(code)))
        assertEquals("cancelSession", server3.calls.last())

        // A result for another transaction is not this download's.
        val card4 = FakeCard().apply { installAs = null; pending += Rsp.installResult(transactionId = ByteArray(16)) }
        assertEquals(Failure.INSTALL_FAILED, failure(DownloadFlow(card4, FakeServers("smdp.example.com" to FakeServer()), FakeUser()).download(code)))
    }

    @Test
    fun installResultGoesToTheAddressInIt() {
        val other = FakeServer("notify.example.com")
        servers.byHost["notify.example.com"] = other
        card.installAs = Rsp.installResult(address = "NOTIFY.example.com")
        val outcome = flow.download(code) as Outcome.Installed
        assertTrue(outcome.notified)
        assertEquals(listOf("handleNotification"), other.calls)
        assertFalse("handleNotification" in server.calls)

        // Unsent results stay on the eUICC for later.
        val card2 = FakeCard()
        val server2 = FakeServer().apply { drop += "handleNotification" }
        val unsent = DownloadFlow(card2, FakeServers("smdp.example.com" to server2), FakeUser()).download(code) as Outcome.Installed
        assertFalse(unsent.notified)
        assertEquals(1, card2.pending.size)
    }

    @Test
    fun discovery() {
        val smds = FakeServer("ds.example.com").apply {
            initiate = Rsp.initiateAuthentication(Rsp.serverSigned1(address = "ds.example.com"))
        }
        val s = FakeServers("ds.example.com" to smds)
        val outcome = DownloadFlow(card, s, user).discover("ds.example.com") as Outcome.Found
        assertEquals("EVENT-1", outcome.events.single().eventId)
        assertEquals(listOf("ds.example.com/SMDS"), s.opened)
        assertEquals("", card.matchingId)
        assertEquals(listOf("initiate", "authenticateClientEs11"), smds.calls)
    }
}

class NotificationFlowTest {
    private val card = FakeCard()
    private val a = FakeServer("a.example.com")
    private val b = FakeServer("b.example.com")
    private val servers = FakeServers("a.example.com" to a, "b.example.com" to b)
    private val owned = mutableSetOf(ICCID_A)
    private val forgotten = mutableListOf<String>()
    private val flow = NotificationFlow(card, servers, { it in owned }, { forgotten += it })

    private val iccidB = Rsp.ICCID_A_BYTES.copyOf().also { it[0] = 0x99.toByte() } // 9949…, not owned

    @Test
    fun sendsOnlyThisAppsProfilesInOrder() {
        card.pending += Rsp.otherNotification(5, NotificationEvents.DISABLE, "a.example.com")
        card.pending += Rsp.otherNotification(3, NotificationEvents.ENABLE, "a.example.com")
        card.pending += Rsp.otherNotification(4, NotificationEvents.ENABLE, "b.example.com", iccid = iccidB)
        card.pending += Rsp.otherNotification(6, NotificationEvents.DELETE, "b.example.com", iccid = null)
        val summary = flow.sendOwned()
        assertEquals(2, summary.sent)
        assertEquals(2, summary.kept)
        assertEquals(0, summary.failed)
        assertEquals(listOf(3, 5), a.notified.map { PendingNotification.parse(it).metadata.seq })
        assertTrue(b.calls.isEmpty())
        assertEquals(2, card.pending.size)
        assertTrue(forgotten.isEmpty())
    }

    @Test
    fun aFailureStopsItsGroupOnly() {
        card.pending += Rsp.otherNotification(1, NotificationEvents.ENABLE, "a.example.com")
        card.pending += Rsp.otherNotification(2, NotificationEvents.DISABLE, "a.example.com")
        card.pending += Rsp.otherNotification(3, NotificationEvents.DELETE, "b.example.com")
        card.pending += Rsp.otherNotification(4, NotificationEvents.ENABLE, "not a host")
        a.drop += "handleNotification"
        val summary = flow.sendOwned()
        assertEquals(1, summary.sent)
        assertEquals(3, summary.failed)
        assertEquals(listOf("handleNotification"), a.calls)
        assertEquals(listOf(ICCID_A), forgotten) // the delete was acknowledged
        assertEquals(3, card.pending.size)
    }

    @Test
    fun nothingOwnedMeansNoNetwork() {
        owned.clear()
        card.pending += Rsp.otherNotification(1, NotificationEvents.ENABLE, "a.example.com")
        assertEquals(1, flow.sendOwned().kept)
        assertTrue(servers.opened.isEmpty())
        assertFalse("info1" in card.calls)
    }

    @Test
    fun listSendAndRemove() {
        card.pending += Rsp.otherNotification(1, NotificationEvents.ENABLE, "a.example.com")
        card.pending += Rsp.otherNotification(2, NotificationEvents.ENABLE, "b.example.com", iccid = iccidB)
        val list = flow.list()
        assertEquals(listOf(true, false), list.map { it.ours })
        assertFalse(flow.send(2)) // not this app's
        assertTrue(b.calls.isEmpty())
        assertTrue(flow.send(1))
        flow.remove(2)
        assertTrue(card.pending.isEmpty())
    }
}
