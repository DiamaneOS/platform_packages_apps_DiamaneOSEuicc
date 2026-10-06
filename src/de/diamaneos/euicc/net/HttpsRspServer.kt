// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.net

import de.diamaneos.euicc.core.Es9
import de.diamaneos.euicc.core.Failure
import de.diamaneos.euicc.core.GsmaCi
import de.diamaneos.euicc.core.HttpRules
import de.diamaneos.euicc.core.Json
import de.diamaneos.euicc.core.JsonException
import de.diamaneos.euicc.core.JsonLimits
import de.diamaneos.euicc.core.JsonObject
import de.diamaneos.euicc.core.RspException
import de.diamaneos.euicc.core.RspServer
import de.diamaneos.euicc.core.RspServers
import de.diamaneos.euicc.core.ServerRole
import de.diamaneos.euicc.core.TlsPolicy
import java.io.IOException
import java.net.URL
import java.security.GeneralSecurityException
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLException
import javax.net.ssl.SSLSession
import javax.net.ssl.X509TrustManager

/** Opens [HttpsRspServer]s that trust only the shipped GSMA CI roots the eUICC also trusts. */
class PinnedServers(private val roots: Map<String, X509Certificate>) : RspServers {
    override fun open(host: String, role: ServerRole, euiccCiIds: List<ByteArray>): RspServer {
        val anchors = GsmaCi.anchors(euiccCiIds, roots)
        if (anchors.isEmpty()) throw RspException(Failure.NO_TRUSTED_CI)
        return HttpsRspServer(host, TlsPolicy(anchors, role))
    }
}

/**
 * ES9+ and ES11 with one RSP server (SGP.22 6.1 to 6.5):
 * - HTTPS to [host] port 443 only; [host] is a validated FQDN from the code, the SM-DS or a
 *   notification. Redirects are never followed: any other status than the function's fails.
 * - The TLS certificate is checked by [policy] against the GSMA CI anchors only, inside the
 *   handshake; the host name check is repeated after it.
 * - A fresh SSLContext per server object, so no TLS session is resumed across RSP sessions
 *   (3.1.2 step 5); "Connection: close", so no request is replayed on a reused connection.
 * - Timeouts on connect and every read; response bodies are size-limited and parsed strictly.
 * - No cookies, no cache, no compression; nothing is logged.
 */
class HttpsRspServer(private val host: String, private val policy: TlsPolicy) : RspServer {
    private val context: SSLContext = SSLContext.getInstance("TLS").apply {
        init(null, arrayOf(PinnedTrustManager(policy, host)), SecureRandom())
    }

    override fun initiateAuthentication(challenge: ByteArray, euiccInfo1: ByteArray) =
        Es9.parseInitiateAuthentication(postJson(Es9.PATH_INITIATE_AUTHENTICATION,
            Es9.initiateAuthenticationRequest(challenge, euiccInfo1, host)))

    override fun authenticateClient(transactionId: ByteArray, authenticateServerResponse: ByteArray) =
        Es9.parseAuthenticateClient(postJson(Es9.PATH_AUTHENTICATE_CLIENT,
            Es9.authenticateClientRequest(transactionId, authenticateServerResponse)))

    override fun authenticateClientEs11(transactionId: ByteArray, authenticateServerResponse: ByteArray) =
        Es9.parseEventEntries(postJson(Es9.PATH_AUTHENTICATE_CLIENT,
            Es9.authenticateClientRequest(transactionId, authenticateServerResponse)))

    override fun getBoundProfilePackage(transactionId: ByteArray, prepareDownloadResponse: ByteArray) =
        Es9.parseBoundProfilePackage(postJson(Es9.PATH_GET_BOUND_PROFILE_PACKAGE,
            Es9.getBoundProfilePackageRequest(transactionId, prepareDownloadResponse),
            Es9.MAX_BPP_RESPONSE_BYTES, Es9.BPP_LIMITS, BPP_READ_TIMEOUT_MS))

    override fun handleNotification(pendingNotification: ByteArray) {
        post(Es9.PATH_HANDLE_NOTIFICATION, Es9.handleNotificationRequest(pendingNotification), READ_TIMEOUT_MS) { conn ->
            HttpRules.checkNotificationResponse(conn.responseCode)
            null
        }
    }

    override fun cancelSession(transactionId: ByteArray, cancelSessionResponse: ByteArray) {
        Es9.parseCancelSession(postJson(Es9.PATH_CANCEL_SESSION,
            Es9.cancelSessionRequest(transactionId, cancelSessionResponse)))
    }

    private fun postJson(
        path: String,
        body: String,
        max: Int = Es9.MAX_RESPONSE_BYTES,
        limits: JsonLimits = Es9.LIMITS,
        readTimeoutMs: Int = READ_TIMEOUT_MS,
    ): JsonObject {
        val bytes = post(path, body, readTimeoutMs) { conn ->
            HttpRules.checkJsonResponse(conn.responseCode, conn.contentType, conn.contentLengthLong, max)
            conn.inputStream.use { HttpRules.readBounded(it, max) }
        }!!
        return try {
            Json.parseObject(bytes, limits)
        } catch (e: JsonException) {
            throw RspException(Failure.INVALID_RESPONSE)
        }
    }

    private fun <T> post(path: String, body: String, readTimeoutMs: Int, read: (HttpsURLConnection) -> T): T {
        val payload = body.toByteArray(Charsets.UTF_8)
        val connection = try {
            URL("https", host, 443, path).openConnection() as HttpsURLConnection
        } catch (e: IOException) {
            throw RspException(Failure.NETWORK)
        }
        try {
            connection.sslSocketFactory = context.socketFactory
            connection.hostnameVerifier = javax.net.ssl.HostnameVerifier { name, session -> verifyAgain(name, session) }
            connection.instanceFollowRedirects = false
            connection.useCaches = false
            connection.allowUserInteraction = false
            connection.connectTimeout = CONNECT_TIMEOUT_MS
            connection.readTimeout = readTimeoutMs
            connection.requestMethod = "POST"
            connection.doOutput = true
            connection.setFixedLengthStreamingMode(payload.size)
            connection.setRequestProperty("User-Agent", Es9.USER_AGENT)
            connection.setRequestProperty("X-Admin-Protocol", Es9.ADMIN_PROTOCOL)
            connection.setRequestProperty("Content-Type", "application/json")
            connection.setRequestProperty("Accept", "application/json")
            connection.setRequestProperty("Accept-Encoding", "identity")
            connection.setRequestProperty("Connection", "close")
            connection.outputStream.use { it.write(payload) }
            return read(connection)
        } catch (e: RspException) {
            throw e
        } catch (e: SSLException) {
            throw RspException(Failure.TLS)
        } catch (e: IOException) {
            throw RspException(if (e.cause is CertificateException) Failure.TLS else Failure.NETWORK)
        } finally {
            connection.disconnect()
        }
    }

    /** The trust manager checked the host already; check the session's leaf again. */
    private fun verifyAgain(name: String, session: SSLSession): Boolean {
        if (!name.equals(host, ignoreCase = true)) return false
        return try {
            policy.check(session.peerCertificates.map { it as X509Certificate }, host)
            true
        } catch (e: GeneralSecurityException) {
            false
        } catch (e: SSLException) {
            false
        } catch (e: ClassCastException) {
            false
        }
    }

    private companion object {
        const val CONNECT_TIMEOUT_MS = 20_000
        const val READ_TIMEOUT_MS = 30_000
        const val BPP_READ_TIMEOUT_MS = 60_000
    }
}

/** Server certificates go through [TlsPolicy] only: no system, user or other CA. */
private class PinnedTrustManager(private val policy: TlsPolicy, private val host: String) : X509TrustManager {
    override fun checkServerTrusted(chain: Array<X509Certificate>?, authType: String?) {
        policy.check(chain?.toList().orEmpty(), host)
    }

    override fun checkClientTrusted(chain: Array<X509Certificate>?, authType: String?) {
        throw CertificateException("not a server")
    }

    override fun getAcceptedIssuers(): Array<X509Certificate> = policy.anchors.toTypedArray()
}
