// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.core

import java.io.ByteArrayInputStream
import java.security.GeneralSecurityException
import java.security.cert.CertPathValidator
import java.security.cert.CertificateException
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.PKIXCertPathChecker
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.util.Date

/** The GSMA RSP Certificate Issuers this app knows (SGP.22 4.5.2, SGP.26 for the test CIs). */
object GsmaCi {
    class Entry(val keyId: String, val name: String, val production: Boolean)

    /** Subject key identifiers, lowercase hex. Only production CIs can become trust anchors. */
    val ENTRIES = listOf(
        Entry("81370f5125d0b1d408d4c3b232e6d25e795bebfb", "GSMA RSP2 Root CI1", true),
        Entry("4c27967ad20c14b391e9601e41e604ad57c0222f", "OISTE GSMA CI G1", true),
        Entry("f54172bdf98a95d65cbeb88a38a1c11d800a85c3", "GSMA test CI (SGP.26, NIST)", false),
        Entry("c0bc70ba36929d43b467ff57570530e57ab8fcd8", "GSMA test CI (SGP.26, brainpool)", false),
        Entry("34eecf13156518d48d30bdf06853404d115f955d", "GSMA test CI (SGP.26 v3, NIST)", false),
        Entry("2209f61cd9ec5c9c854e787341ff83ecf9776a5b", "GSMA test CI (SGP.26 v3, brainpool)", false),
    )

    fun entry(keyId: ByteArray): Entry? = Hex.encode(keyId).let { id -> ENTRIES.firstOrNull { it.keyId == id } }

    /**
     * The key identifier of a shipped root, if it is a known production CI, self-signed with
     * that key, a CA and valid now; else null and the root is not used.
     */
    fun checkRoot(cert: X509Certificate, now: Date = Date()): String? {
        val keyId = Certificates.subjectKeyId(cert)?.let(Hex::encode) ?: return null
        if (ENTRIES.none { it.keyId == keyId && it.production }) return null
        return try {
            cert.checkValidity(now)
            cert.verify(cert.publicKey)
            if (cert.basicConstraints < 0 || cert.subjectX500Principal != cert.issuerX500Principal) null else keyId
        } catch (e: GeneralSecurityException) {
            null
        }
    }

    /** A public name for a CI key identifier, for the dump: the name, else the first 3 bytes. */
    fun describe(keyId: ByteArray): String =
        entry(keyId)?.name ?: "unknown CI ${Hex.encode(keyId.copyOfRange(0, minOf(3, keyId.size)))}"

    /**
     * The trust anchors for one session: the shipped production roots whose key identifier the
     * eUICC lists in euiccCiPKIdListForVerification, in the eUICC's order. Test CIs never count:
     * their private keys are published with SGP.26.
     */
    fun anchors(euiccVerification: List<ByteArray>, shipped: Map<String, X509Certificate>): List<X509Certificate> =
        euiccVerification.mapNotNull { id ->
            val hex = Hex.encode(id)
            if (ENTRIES.any { it.keyId == hex && it.production }) shipped[hex] else null
        }.distinct()
}

/** The certificate role an RSP server's TLS certificate may carry (SGP.22 Annex H). */
enum class ServerRole(val tlsPolicyOid: String) {
    SMDP("2.23.146.1.2.1.3"), // id-rspRole-dp-tls
    SMDS("2.23.146.1.2.1.6"), // id-rspRole-ds-tls
}

/**
 * TLS server certificate checks for ES9+ and ES11 (SGP.22 4.5.2.1 CERT.DP.TLS / CERT.DS.TLS,
 * 4.5.2.2 verification, 3.1.2 step 5):
 * - the chain validates (RFC 5280 path validation) to one of [anchors], the GSMA CI roots the
 *   eUICC also trusts; no system or user CA is ever consulted;
 * - the certificate is valid now, has extended key usage serverAuth and, if a key usage is
 *   present, digitalSignature;
 * - a Certificate Policies extension, if present, contains the TLS role of [role];
 * - a dNSName in subjectAltName matches the host (wildcards as RFC 6125; the CN is ignored).
 * Revocation is not checked: CRLs are optional for the LPA (4.5.2.2) and would mean more
 * connections.
 */
class TlsPolicy(
    val anchors: List<X509Certificate>,
    private val role: ServerRole,
    private val now: () -> Date = { Date() },
) {
    init {
        require(anchors.isNotEmpty()) { "no trust anchors" }
    }

    fun check(chain: List<X509Certificate>, host: String) {
        if (chain.isEmpty()) throw CertificateException("empty chain")
        // Servers may send the CI root itself; the root is the anchor, not part of the path.
        val path = chain.filter { cert -> anchors.none { it == cert } }
        if (path.isEmpty() || path[0] != chain[0]) throw CertificateException("no server certificate")
        try {
            val params = PKIXParameters(anchors.map { TrustAnchor(it, null) }.toSet()).apply {
                isRevocationEnabled = false
                date = now()
                addCertPathChecker(ExtendedKeyUsageHandled)
            }
            val certPath = CertificateFactory.getInstance("X.509").generateCertPath(path)
            CertPathValidator.getInstance("PKIX").validate(certPath, params)
        } catch (e: GeneralSecurityException) {
            throw CertificateException("path validation failed", e)
        }
        checkLeaf(chain[0], host)
    }

    private fun checkLeaf(leaf: X509Certificate, host: String) {
        val usage = try {
            leaf.extendedKeyUsage
        } catch (e: CertificateException) {
            null
        }
        if (usage == null || SERVER_AUTH !in usage) throw CertificateException("no serverAuth usage")
        leaf.keyUsage?.let { if (it.isEmpty() || !it[0]) throw CertificateException("no digitalSignature usage") }
        Certificates.policies(leaf)?.let {
            if (role.tlsPolicyOid !in it) throw CertificateException("wrong certificate role")
        }
        if (Certificates.dnsNames(leaf).none { Fqdn.matches(host, it) }) throw CertificateException("host mismatch")
    }

    /**
     * SGP.22 TLS certificates mark extended key usage critical. RFC 5280 path validation does
     * not process it, so some PKIX implementations (older BouncyCastle, which Android uses)
     * reject the path; checkLeaf checks it instead, as Android's own TrustManagerImpl does.
     */
    private object ExtendedKeyUsageHandled : PKIXCertPathChecker() {
        override fun init(forward: Boolean) {}
        override fun isForwardCheckingSupported() = false
        override fun getSupportedExtensions(): Set<String> = setOf(EXTENDED_KEY_USAGE)
        override fun check(cert: Certificate, unresolvedCritExts: MutableCollection<String>) {
            unresolvedCritExts.remove(EXTENDED_KEY_USAGE)
        }
    }

    private companion object {
        const val SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
        const val EXTENDED_KEY_USAGE = "2.5.29.37"
    }
}

/** X.509 extension readers, on our own DER parser so host and phone read them the same way. */
object Certificates {
    private const val SUBJECT_ALT_NAME = "2.5.29.17"
    private const val CERTIFICATE_POLICIES = "2.5.29.32"
    private const val SUBJECT_KEY_IDENTIFIER = "2.5.29.14"

    fun parse(der: ByteArray): X509Certificate =
        CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(der)) as X509Certificate

    /** subjectAltName dNSName entries ([2] IA5String). */
    fun dnsNames(cert: X509Certificate): List<String> =
        generalNames(cert).filter { it.tag == 0x82 }.map { String(it.value, Charsets.US_ASCII) }

    /** subjectAltName registeredID entries ([8] OBJECT IDENTIFIER): the SM-DP+ OID (4.5.2.1). */
    fun registeredIds(cert: X509Certificate): List<String> =
        generalNames(cert).filter { it.tag == 0x88 }.mapNotNull { runCatching { Der.decodeOid(it.value) }.getOrNull() }

    /** Policy OIDs, or null if the certificate has no Certificate Policies extension. */
    fun policies(cert: X509Certificate): Set<String>? {
        val value = extension(cert, CERTIFICATE_POLICIES) ?: return null
        return try {
            Tlv.one(value, 0x30).children().map { info ->
                require(info.tag == 0x30)
                info.require(0x06).oid()
            }.toSet()
        } catch (e: IllegalArgumentException) {
            throw CertificateException("bad certificate policies")
        }
    }

    /** The subject key identifier, or null. */
    fun subjectKeyId(cert: X509Certificate): ByteArray? = extension(cert, SUBJECT_KEY_IDENTIFIER)?.let {
        runCatching { Tlv.one(it, 0x04).value }.getOrNull()
    }

    private fun generalNames(cert: X509Certificate): List<Tlv> {
        val value = extension(cert, SUBJECT_ALT_NAME) ?: return emptyList()
        return try {
            Tlv.one(value, 0x30).children()
        } catch (e: IllegalArgumentException) {
            throw CertificateException("bad subjectAltName")
        }
    }

    /** The extnValue contents (getExtensionValue wraps them in an OCTET STRING). */
    private fun extension(cert: X509Certificate, oid: String): ByteArray? {
        val wrapped = cert.getExtensionValue(oid) ?: return null
        return try {
            Tlv.one(wrapped, 0x04).value
        } catch (e: IllegalArgumentException) {
            throw CertificateException("bad extension")
        }
    }
}
