// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.fuzz

import de.diamaneos.euicc.core.ActivationCode
import de.diamaneos.euicc.core.CancelReason
import de.diamaneos.euicc.core.CardException
import de.diamaneos.euicc.core.ConfirmRequest
import de.diamaneos.euicc.core.Confirmation
import de.diamaneos.euicc.core.DownloadFlow
import de.diamaneos.euicc.core.Es9
import de.diamaneos.euicc.core.Failure
import de.diamaneos.euicc.core.Json
import de.diamaneos.euicc.core.JsonException
import de.diamaneos.euicc.core.JsonLimits
import de.diamaneos.euicc.core.JsonObject
import de.diamaneos.euicc.core.OperatorId
import de.diamaneos.euicc.core.Outcome
import de.diamaneos.euicc.core.PprCheck
import de.diamaneos.euicc.core.Rsp
import de.diamaneos.euicc.core.RspCard
import de.diamaneos.euicc.core.RspException
import de.diamaneos.euicc.core.RspServer
import de.diamaneos.euicc.core.RspServers
import de.diamaneos.euicc.core.RspUser
import de.diamaneos.euicc.core.ServerRole
import de.diamaneos.euicc.fuzz.ActivationCodeFuzz.asciiLower

/**
 * A whole download (DownloadFlow) against a server whose ES9+ response bodies are the input,
 * read by the real JSON and ES9+ parsers, and an eUICC whose AuthenticateServer,
 * PrepareDownload and notification answers can be input too. Input: flags, then the
 * InitiateAuthentication, AuthenticateClient and GetBoundProfilePackage bodies, the eUICC's
 * install result and its AuthenticateServer response (empty parts take the scripted answer).
 * - download() returns an outcome and throws nothing.
 * - Order: AuthenticateServer, the user's consent, PrepareDownload, the package download, the
 *   install. Nothing is installed without an Accept. Cancel reasons are postponed or timeout.
 * - The address the server signed reads as the code's host, whichever copy the eUICC reads.
 * - The metadata the eUICC receives has, under every reader model, the class and rules the
 *   user agreed to, no extra events, and the same owner when there are rules.
 * - Connections go only to the code's host and the install result's address.
 */
object DownloadFlowFuzz {
    private const val HOST = "smdp.example.com"

    /** -Dfuzz.trace=true prints each input's outcome and steps, to see how deep the seeds go. */
    private val TRACE = System.getProperty("fuzz.trace") == "true"

    @JvmStatic
    fun fuzzerTestOneInput(data: ByteArray) {
        val (flags, initiate, client, bpp, install, auth) = Parts.split(data, 6).let { Six(it) }
        val f = flags.copyOf(4)
        val log = mutableListOf<String>()
        val card = Card(log, f[0].toInt(), install, auth)
        val server = Server(log, initiate, client, bpp)
        val opened = mutableListOf<String>()
        val servers = RspServers { host, _, ids ->
            if (ids.isEmpty()) throw RspException(Failure.NO_TRUSTED_CI)
            opened += host
            if (host == HOST) server else throw RspException(Failure.NETWORK)
        }
        val user = User(log, f[1].toInt())
        val oid = if (f[2].toInt() and 1 != 0) "$" + "1.3.6.1.4.1.99999.1" else ""
        val cc = if (f[2].toInt() and 2 != 0) (if (oid.isEmpty()) "$$" else "$") + "1" else ""
        val code = ActivationCode.parse("LPA:1$$HOST\$MATCHING-1$oid$cc")
        val outcome = DownloadFlow(card, servers, user).download(code)
        if (TRACE) println("outcome=${outcome.javaClass.simpleName} ${(outcome as? Outcome.Failed)?.failure ?: ""} steps=$log")

        val at = { name: String -> log.indexOfFirst { it == name } }
        val load = at("load")
        if (load >= 0) {
            val confirm = at("confirm:accept")
            invariant(confirm in 0 until load) { "installed without consent" }
            invariant(at("prepare") in (confirm + 1) until load) { "PrepareDownload out of order" }
            invariant(at("getBpp") in (confirm + 1) until load) { "package download out of order" }
            val agreed = user.request!!.metadata
            val sent = card.loaded!!
            val shown = MetadataModels.shown(agreed)
            val metadata = framework(sent) ?: throw Violation("installed package without metadata segments")
            for (model in MetadataModels.MODELS) {
                val v = MetadataModels.read(metadata, model) ?: throw Violation("installed metadata unreadable under $model")
                invariant(v.profileClass == shown.profileClass && v.ppr == shown.ppr) { "installed class or rules differ under $model" }
                invariant(shown.events.containsAll(v.events)) { "installed events exceed the consent under $model" }
                if (agreed.policyRules != 0) invariant(v.owner == shown.owner) { "installed owner differs under $model" }
            }
        } else {
            invariant(outcome !is Outcome.Installed) { "Installed without a load" }
        }
        if (at("confirm:accept") < 0) invariant(at("prepare") < 0 && at("getBpp") < 0) { "went on without consent" }
        val authAt = at("authenticateServer")
        if (authAt >= 0) {
            val signed = card.signed1!!
            val addresses = RefDer.decode(signed).single().children().filter { it.packedTag == 0x83 || (it.tagClass == 2 && it.number == 3L) }
            for (a in addresses) invariant(String(a.content, Charsets.UTF_8).asciiLower() == HOST) { "signed address is not the host" }
        }
        for (r in card.cancelReasons) {
            invariant(r == CancelReason.POSTPONED || (r == CancelReason.TIMEOUT && at("confirm:none") >= 0)) { "cancel reason $r" }
        }
        val notified = card.notifiedHost
        invariant(opened.all { it == HOST || it == notified }) { "contacted a host the user did not agree to" }
    }

    private class Six(l: List<ByteArray>) {
        val p = l
        operator fun component1() = p[0]
        operator fun component2() = p[1]
        operator fun component3() = p[2]
        operator fun component4() = p[3]
        operator fun component5() = p[4]
        operator fun component6() = p[5]
    }

    /** The '88' contents the eUICC joins, from the first [1] component of the package, as EuiccPort sends it. */
    private fun framework(bpp: ByteArray): ByteArray? = try {
        val seq = RefDer.decode(bpp).single().children().first { it.packedTag == 0xA1 }
        val segments = seq.children().filter { it.packedTag == 0x88 }
        de.diamaneos.euicc.core.Der.concat(*segments.map { it.content.copyOfRange(0, it.content.size - 8) }.toTypedArray())
    } catch (e: Exception) {
        null
    }

    private fun body(bytes: ByteArray, limits: JsonLimits = Es9.LIMITS): JsonObject = try {
        Json.parseObject(bytes, limits)
    } catch (e: JsonException) {
        throw RspException(Failure.INVALID_RESPONSE)
    }

    private class Server(val log: MutableList<String>, val initiate: ByteArray, val client: ByteArray, val bpp: ByteArray) : RspServer {
        override fun initiateAuthentication(challenge: ByteArray, euiccInfo1: ByteArray): Es9.InitiateAuthentication {
            log += "initiate"
            return Es9.parseInitiateAuthentication(body(initiate))
        }
        override fun authenticateClient(transactionId: ByteArray, authenticateServerResponse: ByteArray): Es9.AuthenticateClient {
            log += "authenticateClient"
            return Es9.parseAuthenticateClient(body(client))
        }
        override fun authenticateClientEs11(transactionId: ByteArray, authenticateServerResponse: ByteArray) = emptyList<Es9.EventEntry>()
        override fun getBoundProfilePackage(transactionId: ByteArray, prepareDownloadResponse: ByteArray): Pair<ByteArray, ByteArray> {
            log += "getBpp"
            return Es9.parseBoundProfilePackage(body(bpp, Es9.BPP_LIMITS))
        }
        override fun handleNotification(pendingNotification: ByteArray) {
            log += "handleNotification"
        }
        override fun cancelSession(transactionId: ByteArray, cancelSessionResponse: ByteArray) {
            log += "cancelSession"
        }
    }

    private class Card(val log: MutableList<String>, val flags: Int, val install: ByteArray, val auth: ByteArray) : RspCard {
        var signed1: ByteArray? = null
        var loaded: ByteArray? = null
        var notifiedHost: String? = null
        val cancelReasons = mutableListOf<Int>()
        private var txid = Rsp.TRANSACTION_ID

        override fun euiccInfo1() = Rsp.euiccInfo1()
        override fun euiccChallenge() = Rsp.CHALLENGE
        override fun authenticateServer(matchingId: String, auth: Es9.InitiateAuthentication): ByteArray {
            log += "authenticateServer"
            signed1 = auth.serverSigned1
            txid = auth.transactionId
            if (flags and 1 != 0) throw CardException(6)
            return if (this.auth.isEmpty()) Rsp.authenticateServerOk(txid) else this.auth
        }
        override fun prepareDownload(hashCc: ByteArray?, client: Es9.AuthenticateClient): ByteArray {
            log += "prepare"
            return Rsp.prepareDownloadOk(txid)
        }
        override fun loadBoundProfilePackage(bpp: ByteArray): ByteArray {
            log += "load"
            loaded = bpp
            if (flags and 2 != 0) throw CardException(-1)
            return ByteArray(0)
        }
        override fun cancelSession(transactionId: ByteArray, reason: Int): ByteArray {
            log += "cancel"
            cancelReasons += reason
            return Rsp.cancelSessionOk()
        }
        override fun notifications(events: Int): List<ByteArray> {
            if (loaded == null) return emptyList()
            val n = if (install.isEmpty()) Rsp.installResult(transactionId = txid) else install
            notifiedHost = de.diamaneos.euicc.core.PendingNotification.parseOrNull(n)?.metadata?.address
                ?.let { de.diamaneos.euicc.core.Fqdn.normalise(it) }
            return listOf(n)
        }
        override fun removeNotification(seq: Int) {}
        override fun hasOperationalProfile() = flags and 4 != 0
        override fun pprCheck(rules: Int, owner: OperatorId?) = when ((flags shr 3) and 3) {
            1 -> PprCheck.CONSENT_REQUIRED
            2 -> PprCheck.FORBIDDEN
            else -> PprCheck.ALLOWED
        }
    }

    private class User(val log: MutableList<String>, val flags: Int) : RspUser {
        var request: ConfirmRequest? = null
        override val cancelled = false
        override fun confirm(request: ConfirmRequest): Confirmation? {
            this.request = request
            ConsentChecks.check(request.metadata)
            return when (flags and 3) {
                1 -> null.also { log += "confirm:none" }
                2 -> Confirmation.Decline.also { log += "confirm:decline" }
                else -> Confirmation.Accept(if (flags and 4 != 0) "CODE-1" else null).also { log += "confirm:accept" }
            }
        }
    }
}
