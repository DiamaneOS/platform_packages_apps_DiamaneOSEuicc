// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.core

/** An eUICC card command failed with an EuiccCardManager result code (positive: SGP.22 error). */
class CardException(val code: Int) : Exception("card result $code")

/** Whether the eUICC's Rules Authorisation Table allows a profile's policy rules (SGP.22 2.9.2.3). */
enum class PprCheck { ALLOWED, CONSENT_REQUIRED, FORBIDDEN }

/**
 * The ES10b and ES10c commands an RSP session needs (SGP.22 5.7), on one eUICC. Every method
 * throws [CardException] when the card or the framework returns an error.
 */
interface RspCard {
    /** EUICCInfo1 (5.7.8), whole. */
    fun euiccInfo1(): ByteArray

    /** GetEUICCChallenge (5.7.7): 16 bytes. Starts a new RSP session on the eUICC. */
    fun euiccChallenge(): ByteArray

    /** AuthenticateServer (5.7.13); the framework adds ctxParams1 with [matchingId] and DeviceInfo. */
    fun authenticateServer(matchingId: String, auth: Es9.InitiateAuthentication): ByteArray

    /** PrepareDownload (5.7.5). */
    fun prepareDownload(hashCc: ByteArray?, client: Es9.AuthenticateClient): ByteArray

    /** LoadBoundProfilePackage (5.7.6); the framework segments the package (2.5.5). */
    fun loadBoundProfilePackage(bpp: ByteArray): ByteArray

    /** CancelSession (5.7.14): the signed CancelSessionResponse. */
    fun cancelSession(transactionId: ByteArray, reason: Int): ByteArray

    /** RetrieveNotificationsList (5.7.10) for NotificationEvents bits: each PendingNotification. */
    fun notifications(events: Int): List<ByteArray>

    /** RemoveNotificationFromList (5.7.11). */
    fun removeNotification(seq: Int)

    /** Whether an operational profile is installed (PPR1 check, 3.1.3 step 7c). */
    fun hasOperationalProfile(): Boolean

    /** GetRAT (5.7.22, 2.9.2): whether the policy rules [rules] (POLICY_RULE_* bits) of [owner] are allowed. */
    fun pprCheck(rules: Int, owner: OperatorId?): PprCheck
}

/** ES9+ and ES11 functions of one RSP server, over pinned HTTPS. Methods throw [RspException]. */
interface RspServer {
    fun initiateAuthentication(challenge: ByteArray, euiccInfo1: ByteArray): Es9.InitiateAuthentication
    fun authenticateClient(transactionId: ByteArray, authenticateServerResponse: ByteArray): Es9.AuthenticateClient
    fun authenticateClientEs11(transactionId: ByteArray, authenticateServerResponse: ByteArray): List<Es9.EventEntry>
    /** The transaction ID the server returned, and the Bound Profile Package. */
    fun getBoundProfilePackage(transactionId: ByteArray, prepareDownloadResponse: ByteArray): Pair<ByteArray, ByteArray>
    fun handleNotification(pendingNotification: ByteArray)
    fun cancelSession(transactionId: ByteArray, cancelSessionResponse: ByteArray)
}

/** Opens a connection to [host] that trusts only the GSMA CIs in [euiccCiIds] that this app ships. */
fun interface RspServers {
    /** Throws [RspException] with [Failure.NO_TRUSTED_CI] when no shipped root is in the list. */
    fun open(host: String, role: ServerRole, euiccCiIds: List<ByteArray>): RspServer
}

/** Where a session is, for the progress text. */
enum class Step { READING_EUICC, CONNECTING, CHECKING_SERVER, AUTHENTICATING, CONFIRMING, PREPARING, DOWNLOADING, INSTALLING, NOTIFYING }

/** What the user is asked after ES9+.AuthenticateClient (3.1.3 step 8). */
class ConfirmRequest(
    val host: String,
    val metadata: ProfileMetadata,
    val confirmationCodeRequired: Boolean,
    /** The RAT asks for the user's consent to the profile's policy rules. */
    val pprConsentRequired: Boolean,
)

sealed interface Confirmation {
    /** Go ahead; [confirmationCode] when one was asked for. */
    class Accept(val confirmationCode: String?) : Confirmation

    /** Not now (CancelSession reason postponed: the code stays usable). */
    data object Decline : Confirmation
}

/** The user's side of an RSP session. */
interface RspUser {
    /** Checked between steps; a cancel before the package download keeps the code usable. */
    val cancelled: Boolean

    fun step(step: Step) {}

    /** Asks for the confirmation; null if there was no answer in time. */
    fun confirm(request: ConfirmRequest): Confirmation?
}

sealed interface Outcome {
    /** The profile is on the eUICC. [notified]: the install result reached the SM-DP+. */
    class Installed(val metadata: ProfileMetadata, val notified: Boolean) : Outcome

    /** Dry run: the server passed TLS and the eUICC's AuthenticateServer checks. */
    class Checked(val serverCi: String, val svn: Version) : Outcome

    /** SM-DS discovery: the events waiting for this eUICC (may be empty). */
    class Found(val events: List<Es9.EventEntry>) : Outcome

    /** Stopped by the user before the package download. */
    data object Cancelled : Outcome

    class Failed(val error: RspException) : Outcome {
        val failure: Failure get() = error.failure
    }
}

/**
 * One SGP.22 consumer RSP session (v2.5 sections 3.1.2 and 3.1.3), on [card] with servers from
 * [servers]. Rules:
 * - Before ES9+.AuthenticateClient the server has not seen the MatchingID, so stopping there
 *   costs nothing; the dry run and discovery never get further.
 * - Every stop after AuthenticateClient and before GetBoundProfilePackage cancels the session on
 *   the eUICC and the server with reason "postponed" (or "timeout" when the user did not
 *   answer), the only reasons that keep the operator's order usable (5.7.14).
 * - After GetBoundProfilePackage the package is installed; the eUICC's install result goes to
 *   the address in it.
 * [installed] records the ICCID of a profile this app installed, before its notification.
 */
class DownloadFlow(
    private val card: RspCard,
    private val servers: RspServers,
    private val user: RspUser,
    private val installed: (String) -> Unit = {},
) {
    private class Session(
        val host: String,
        val server: RspServer,
        val transactionId: ByteArray,
        val authenticateServerResponse: ByteArray,
        val euiccInfo1: EuiccInfo1,
        val serverCi: ByteArray,
    )

    private class Stop(val outcome: Outcome) : Exception()

    /** Download and install the profile of [code] (3.1.3 option a, or b with an SM-DS event). */
    fun download(code: ActivationCode): Outcome = guarded {
        val session = authenticate(code.smdpAddress, ServerRole.SMDP, code.matchingId, code.smdpOid)
        if (user.cancelled) return@guarded cancelOnCard(session, Outcome.Cancelled)

        user.step(Step.AUTHENTICATING)
        val client = try {
            session.server.authenticateClient(session.transactionId, session.authenticateServerResponse)
        } catch (e: RspException) {
            // A refusal ends the server's session; after a lost answer it may still be open.
            return@guarded if (e.failure == Failure.SERVER_REFUSED) cancelOnCard(session, Outcome.Failed(e))
            else cancelBoth(session, Outcome.Failed(e))
        }
        val signed2: SmdpSigned2
        val metadata: ProfileMetadata
        try {
            signed2 = SmdpSigned2.parse(client.smdpSigned2)
            metadata = ProfileMetadata.parse(client.profileMetadata)
        } catch (e: IllegalArgumentException) {
            return@guarded cancelBoth(session, failed(Failure.INVALID_RESPONSE))
        }
        if (!client.transactionId.contentEquals(session.transactionId) ||
            !signed2.transactionId.contentEquals(session.transactionId)) {
            return@guarded cancelBoth(session, failed(Failure.SERVER_MISMATCH))
        }

        // Profile policy rules (3.1.3 step 7).
        var pprConsent = false
        if (metadata.policyRules != 0) {
            if (metadata.ppr1 && card.hasOperationalProfile()) {
                return@guarded cancelBoth(session, failed(Failure.PPR_NOT_ALLOWED))
            }
            when (card.pprCheck(metadata.policyRules, metadata.owner)) {
                PprCheck.FORBIDDEN -> return@guarded cancelBoth(session, failed(Failure.PPR_NOT_ALLOWED))
                PprCheck.CONSENT_REQUIRED -> pprConsent = true
                PprCheck.ALLOWED -> {}
            }
        }
        if (user.cancelled) return@guarded cancelBoth(session, Outcome.Cancelled)

        // Confirmation, with the confirmation code if the code or the server asks for one.
        val ccRequired = signed2.ccRequired || code.confirmationCodeRequired
        user.step(Step.CONFIRMING)
        val answer = user.confirm(ConfirmRequest(session.host, metadata, ccRequired, pprConsent))
        val hashCc: ByteArray? = when (answer) {
            null -> return@guarded cancelBoth(session, failed(Failure.USER_TIMEOUT), CancelReason.TIMEOUT)
            Confirmation.Decline -> return@guarded cancelBoth(session, Outcome.Cancelled)
            is Confirmation.Accept -> if (!ccRequired) null else {
                val cc = ConfirmationCode.normalise(answer.confirmationCode)
                    ?: return@guarded cancelBoth(session, failed(Failure.CONFIRMATION_CODE_MISSING))
                ConfirmationCode.hash(cc, session.transactionId)
            }
        }
        if (user.cancelled) return@guarded cancelBoth(session, Outcome.Cancelled)

        user.step(Step.PREPARING)
        val prepared = try {
            card.prepareDownload(hashCc, client)
        } catch (e: CardException) {
            return@guarded cancelBoth(session, Outcome.Failed(RspException(Failure.CARD, cardCode = e.code)))
        }
        if (!CardResponses.prepareDownloadOk(prepared, session.transactionId)) {
            return@guarded cancelBoth(session, failed(Failure.CARD))
        }
        if (user.cancelled) return@guarded cancelBoth(session, Outcome.Cancelled)

        // Point of no return: the server marks the profile downloaded.
        user.step(Step.DOWNLOADING)
        val (bppTransaction, bpp) = try {
            session.server.getBoundProfilePackage(session.transactionId, prepared)
        } catch (e: RspException) {
            // A refusal here is final for this session (e.g. a wrong confirmation code; 3.1.3.2).
            return@guarded if (e.failure == Failure.SERVER_REFUSED) cancelOnCard(session, Outcome.Failed(e))
            else cancelBoth(session, Outcome.Failed(e))
        }
        if (!bppTransaction.contentEquals(session.transactionId)) {
            return@guarded cancelBoth(session, failed(Failure.SERVER_MISMATCH))
        }
        // 3.1.3.2: the rules in the package must be the ones the user agreed to.
        ProfileMetadata.fromBoundProfilePackage(bpp)?.let {
            if (it.policyRules != metadata.policyRules) return@guarded cancelBoth(session, failed(Failure.PPR_NOT_ALLOWED))
        }

        user.step(Step.INSTALLING)
        val loadError = try {
            card.loadBoundProfilePackage(bpp)
            null
        } catch (e: CardException) {
            e
        }
        // The eUICC keeps a signed install result for every package that reached it (3.1.3.3).
        val result = installResult(session.transactionId)
            ?: return@guarded cancelBoth(session, Outcome.Failed(RspException(Failure.INSTALL_FAILED, cardCode = loadError?.code)))
        val install = result.install!!
        if (install.success) result.metadata.iccid?.let(installed)
        user.step(Step.NOTIFYING)
        val notified = sendInstallResult(result, session)
        if (install.success) Outcome.Installed(metadata, notified)
        else Outcome.Failed(RspException(Failure.INSTALL_FAILED, cardCode = install.errorReason))
    }

    /**
     * Dry run: TLS to [code]'s SM-DP+, ES9+.InitiateAuthentication, the address, challenge and
     * OID checks, and the eUICC's AuthenticateServer with an empty MatchingID; then the eUICC
     * session is cancelled. The server never sees the MatchingID: the code is not used.
     */
    fun check(code: ActivationCode): Outcome = guarded {
        val session = authenticate(code.smdpAddress, ServerRole.SMDP, "", code.smdpOid)
        cancelOnCard(session, Outcome.Checked(GsmaCi.describe(session.serverCi), session.euiccInfo1.svn))
    }

    /** SM-DS event retrieval (3.6.2, ES11 5.8): asks [smdsHost] for events for this eUICC. */
    fun discover(smdsHost: String): Outcome = guarded {
        val session = authenticate(smdsHost, ServerRole.SMDS, "", null)
        if (user.cancelled) return@guarded cancelOnCard(session, Outcome.Cancelled)
        user.step(Step.AUTHENTICATING)
        val events = session.server.authenticateClientEs11(session.transactionId, session.authenticateServerResponse)
        cancelOnCard(session, Outcome.Found(events))
    }

    /** Common mutual authentication up to and including ES10b.AuthenticateServer (3.1.2 steps 1-14). */
    private fun authenticate(host: String, role: ServerRole, matchingId: String, smdpOid: String?): Session {
        user.step(Step.READING_EUICC)
        val info1Bytes = card.euiccInfo1()
        val info1 = try {
            EuiccInfo1.parse(info1Bytes)
        } catch (e: IllegalArgumentException) {
            throw Stop(failed(Failure.CARD))
        }
        val server = servers.open(host, role, info1.ciForVerification)
        val challenge = card.euiccChallenge()
        if (challenge.size != 16) throw Stop(failed(Failure.CARD))
        if (user.cancelled) throw Stop(Outcome.Cancelled)

        user.step(Step.CONNECTING)
        val auth = server.initiateAuthentication(challenge, info1Bytes)
        val signed1 = try {
            ServerSigned1.parse(auth.serverSigned1)
        } catch (e: IllegalArgumentException) {
            throw Stop(failed(Failure.INVALID_RESPONSE))
        }
        // 3.1.2 step 10: the address the server signed must be the one we asked.
        if (!signed1.transactionId.contentEquals(auth.transactionId) ||
            !signed1.euiccChallenge.contentEquals(challenge) ||
            !signed1.serverAddress.equals(host, ignoreCase = true)) {
            throw Stop(failed(Failure.SERVER_MISMATCH))
        }
        val ciToBeUsed = try {
            Tlv.one(auth.euiccCiPkIdToBeUsed, 0x04).value
        } catch (e: IllegalArgumentException) {
            throw Stop(failed(Failure.INVALID_RESPONSE))
        }
        if (info1.ciForSigning.none { it.contentEquals(ciToBeUsed) }) throw Stop(failed(Failure.SERVER_MISMATCH))
        // 3.1.3 step 1: the OID from the code must be the one in CERT.DPauth.ECDSA.
        if (smdpOid != null) {
            val ids = try {
                Certificates.registeredIds(Certificates.parse(auth.serverCertificate))
            } catch (e: java.security.GeneralSecurityException) {
                throw Stop(failed(Failure.INVALID_RESPONSE))
            }
            if (smdpOid !in ids) throw Stop(failed(Failure.OID_MISMATCH))
        }
        if (user.cancelled) throw Stop(Outcome.Cancelled)

        user.step(Step.CHECKING_SERVER)
        val response = try {
            card.authenticateServer(matchingId, auth)
        } catch (e: CardException) {
            throw Stop(Outcome.Failed(RspException(Failure.CARD_REFUSED_SERVER, cardCode = e.code)))
        }
        val session = Session(host, server, auth.transactionId, response, info1, ciToBeUsed)
        if (!CardResponses.authenticateServerOk(response, auth.transactionId)) {
            throw Stop(cancelOnCard(session, failed(Failure.CARD_REFUSED_SERVER)))
        }
        return session
    }

    /** The eUICC's install result for [transactionId], if it kept one. */
    private fun installResult(transactionId: ByteArray): PendingNotification? = try {
        card.notifications(NotificationEvents.INSTALL)
            .mapNotNull { PendingNotification.parseOrNull(it) }
            .firstOrNull { it.install?.transactionId?.contentEquals(transactionId) == true }
    } catch (e: CardException) {
        null
    }

    /** ES9+.HandleNotification to the address in the result, then removal from the eUICC (3.1.3.3, 3.5). */
    private fun sendInstallResult(result: PendingNotification, session: Session): Boolean {
        val host = Fqdn.normalise(result.metadata.address) ?: return false
        return try {
            val server = if (host == session.host) session.server
            else servers.open(host, ServerRole.SMDP, session.euiccInfo1.ciForVerification)
            server.handleNotification(result.raw)
            card.removeNotification(result.metadata.seq)
            true
        } catch (e: RspException) {
            false
        } catch (e: CardException) {
            true // sent; the eUICC keeps it until a later removal
        }
    }

    /** Clears the eUICC's session (the server never saw the MatchingID, or has ended its side). */
    private fun cancelOnCard(session: Session, outcome: Outcome, reason: Int = CancelReason.POSTPONED): Outcome {
        try {
            card.cancelSession(session.transactionId, reason)
        } catch (e: CardException) {
            // The eUICC may have dropped the session already.
        }
        return outcome
    }

    /** ES10b.CancelSession, then ES9+.CancelSession with the eUICC's signed response (3.1.3.1). */
    private fun cancelBoth(session: Session, outcome: Outcome, reason: Int = CancelReason.POSTPONED): Outcome {
        val signed = try {
            card.cancelSession(session.transactionId, reason)
        } catch (e: CardException) {
            return outcome
        }
        if (CardResponses.cancelSessionOk(signed)) {
            try {
                session.server.cancelSession(session.transactionId, signed)
            } catch (e: RspException) {
                // Best effort: the server also ends the session on its own.
            }
        }
        return outcome
    }

    private inline fun guarded(block: () -> Outcome): Outcome = try {
        block()
    } catch (e: Stop) {
        e.outcome
    } catch (e: RspException) {
        Outcome.Failed(e)
    } catch (e: CardException) {
        Outcome.Failed(RspException(Failure.CARD, cardCode = e.code))
    }

    private fun failed(failure: Failure) = Outcome.Failed(RspException(failure))
}
