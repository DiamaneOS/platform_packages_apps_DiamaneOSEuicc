// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.fuzz

import de.diamaneos.euicc.core.Certificates
import de.diamaneos.euicc.core.Fqdn
import de.diamaneos.euicc.core.GsmaCi
import de.diamaneos.euicc.core.ServerRole
import de.diamaneos.euicc.core.TlsFixtures
import de.diamaneos.euicc.core.TlsPolicy
import java.security.GeneralSecurityException
import java.util.Calendar
import java.util.TimeZone

/**
 * The server certificate from ES9+.InitiateAuthentication (the SM-DP+ OID check) and the TLS
 * chain checks (TlsPolicy, the extension readers, GsmaCi.checkRoot), on DER the host JDK parses.
 * Only the synthetic test certificates of TlsFixtures are anchors and seeds.
 * - Only GeneralSecurityException may come out of the readers and the policy.
 * - A chain the policy accepts verifies with the anchor's key and names the host.
 */
object CertificateFuzz {
    private val ci by lazy { Certificates.parse(pem(TlsFixtures.TEST_CI)) }
    private val now = Calendar.getInstance(TimeZone.getTimeZone("UTC")).apply {
        clear()
        set(2026, 9, 6)
    }.time
    private val policies by lazy { ServerRole.entries.map { TlsPolicy(listOf(ci), it) { now } } }
    private val HOSTS = listOf("smdp.example.com", "a.rsp.example.com", "ds.example.com")

    @JvmStatic
    fun fuzzerTestOneInput(data: ByteArray) {
        val cert = try {
            Certificates.parse(data)
        } catch (e: GeneralSecurityException) {
            return
        }
        val names = allowed { Certificates.dnsNames(cert) }
        allowed { Certificates.registeredIds(cert) }
        allowed { Certificates.policies(cert) }
        Certificates.subjectKeyId(cert)
        GsmaCi.checkRoot(cert, now)
        for (policy in policies) for (host in HOSTS) for (chain in listOf(listOf(cert), listOf(cert, ci))) {
            val ok = allowed {
                policy.check(chain, host)
                true
            } == true
            if (ok) {
                invariant(runCatching { cert.verify(ci.publicKey) }.isSuccess) { "accepted a leaf the anchor did not sign" }
                invariant(names.orEmpty().any { Fqdn.matches(host, it) }) { "accepted a leaf without the host" }
            }
        }
    }

    private inline fun <T> allowed(block: () -> T): T? = try {
        block()
    } catch (e: GeneralSecurityException) {
        null
    }

    fun pem(text: String): ByteArray = java.util.Base64.getMimeDecoder().decode(
        text.lines().filter { !it.startsWith("-----") }.joinToString(""))
}
