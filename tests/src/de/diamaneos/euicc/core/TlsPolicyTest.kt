// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.core

import java.io.ByteArrayInputStream
import java.io.File
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Calendar
import java.util.Date
import java.util.TimeZone
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class TlsPolicyTest {
    private fun cert(pem: String) = CertificateFactory.getInstance("X.509")
        .generateCertificate(ByteArrayInputStream(pem.toByteArray())) as X509Certificate

    private fun date(year: Int, month: Int, day: Int): Date = Calendar.getInstance(TimeZone.getTimeZone("UTC"))
        .apply { clear(); set(year, month - 1, day) }.time

    private val ci = cert(TlsFixtures.TEST_CI)
    private val inTerm = { date(2026, 10, 6) }
    private val smdp = TlsPolicy(listOf(ci), ServerRole.SMDP, inTerm)

    private fun refused(policy: TlsPolicy, chain: List<X509Certificate>, host: String) {
        assertThrows(CertificateException::class.java) { policy.check(chain, host) }
    }

    @Test
    fun acceptsAnSmdpCertificateFromTheAnchor() {
        val leaf = cert(TlsFixtures.LEAF_DP)
        smdp.check(listOf(leaf), "smdp.example.com")
        smdp.check(listOf(leaf), "SMDP.Example.com")
        smdp.check(listOf(leaf), "eu.rsp.example.com") // *.rsp.example.com
        smdp.check(listOf(leaf, ci), "smdp.example.com") // the server may send the root
        // A policy extension is optional (SGP.22 4.5.2.2).
        smdp.check(listOf(cert(TlsFixtures.LEAF_NOPOLICY)), "smdp.example.com")
    }

    @Test
    fun refusesEverythingElse() {
        val leaf = cert(TlsFixtures.LEAF_DP)
        refused(smdp, listOf(leaf), "other.example.com")
        refused(smdp, listOf(leaf), "a.b.rsp.example.com")
        refused(smdp, listOf(leaf), "rsp.example.com")
        refused(smdp, emptyList(), "smdp.example.com")
        refused(smdp, listOf(ci), "smdp.example.com")
        // Signed by another root, also when that root is sent along.
        refused(smdp, listOf(cert(TlsFixtures.LEAF_FOREIGN)), "smdp.example.com")
        refused(smdp, listOf(cert(TlsFixtures.LEAF_FOREIGN), cert(TlsFixtures.OTHER_CI)), "smdp.example.com")
        refused(smdp, listOf(cert(TlsFixtures.LEAF_EXPIRED)), "smdp.example.com")
        refused(smdp, listOf(cert(TlsFixtures.LEAF_NOEKU)), "smdp.example.com")
        refused(smdp, listOf(cert(TlsFixtures.LEAF_CLIENTONLY)), "smdp.example.com")
        // An SM-DS certificate is not an SM-DP+ one.
        refused(smdp, listOf(cert(TlsFixtures.LEAF_DS)), "ds.example.com")
        TlsPolicy(listOf(ci), ServerRole.SMDS, inTerm).check(listOf(cert(TlsFixtures.LEAF_DS)), "ds.example.com")
        // Outside the validity period.
        refused(TlsPolicy(listOf(ci), ServerRole.SMDP) { date(2027, 3, 1) }, listOf(leaf), "smdp.example.com")
        // A root the eUICC does not list is no anchor at all.
        refused(TlsPolicy(listOf(cert(TlsFixtures.OTHER_CI)), ServerRole.SMDP, inTerm), listOf(leaf), "smdp.example.com")
        assertThrows(IllegalArgumentException::class.java) { TlsPolicy(emptyList(), ServerRole.SMDP) }
    }

    /** Recorded public certificates of a live SM-DP+ and the GSMA root SM-DS, against the shipped CI1 root. */
    @Test
    fun liveServersChainToTheShippedRoot() {
        val ci1 = shippedRoots().getValue(GsmaCi.ENTRIES[0].keyId)
        val smdp = TlsPolicy(listOf(ci1), ServerRole.SMDP, inTerm)
        smdp.check(listOf(cert(TlsFixtures.TRUPHONE_SMDP)), "rsp.truphone.com")
        smdp.check(listOf(cert(TlsFixtures.TRUPHONE_SMDP)), "smdp.io")
        refused(smdp, listOf(cert(TlsFixtures.TRUPHONE_SMDP)), "rsp.example.com")
        refused(smdp, listOf(cert(TlsFixtures.GSMA_SMDS)), "lpa.ds.gsma.com")
        TlsPolicy(listOf(ci1), ServerRole.SMDS, inTerm).check(listOf(cert(TlsFixtures.GSMA_SMDS)), "lpa.ds.gsma.com")
        // The SM-DP+ OID an activation code could name (SGP.22 4.1).
        assertEquals(listOf("1.3.6.1.4.1.30277.1.1.1"), Certificates.registeredIds(cert(TlsFixtures.TRUPHONE_SMDP)))
        assertEquals(setOf("2.23.146.1.2.1.3"), Certificates.policies(cert(TlsFixtures.TRUPHONE_SMDP)))
        // Not trusted under the other shipped CI.
        val oiste = shippedRoots().getValue(GsmaCi.ENTRIES[1].keyId)
        refused(TlsPolicy(listOf(oiste), ServerRole.SMDP, inTerm), listOf(cert(TlsFixtures.TRUPHONE_SMDP)), "rsp.truphone.com")
    }

    @Test
    fun anchorsAreTheShippedProductionRootsTheEuiccLists() {
        val shipped = shippedRoots()
        val ci1 = Hex.decode(GsmaCi.ENTRIES[0].keyId)!!
        val oiste = Hex.decode(GsmaCi.ENTRIES[1].keyId)!!
        val test = Hex.decode("f54172bdf98a95d65cbeb88a38a1c11d800a85c3")!!
        val unknown = ByteArray(20) { 7 }
        assertEquals(listOf(shipped[GsmaCi.ENTRIES[0].keyId]), GsmaCi.anchors(listOf(test, ci1, unknown), shipped))
        assertEquals(listOf(shipped[GsmaCi.ENTRIES[1].keyId], shipped[GsmaCi.ENTRIES[0].keyId]),
            GsmaCi.anchors(listOf(oiste, ci1, ci1), shipped))
        // A test CI never becomes an anchor, even if a certificate for it were shipped.
        assertTrue(GsmaCi.anchors(listOf(test), mapOf(Hex.encode(test) to ci)).isEmpty())
        assertTrue(GsmaCi.anchors(emptyList(), shipped).isEmpty())
    }

    /** The two roots in res/raw: the GSMA's production CIs, self-signed, valid until 2052 and 2059. */
    @Test
    fun shippedRootsAreTheGsmaProductionCis() {
        val roots = shippedRoots()
        assertEquals(setOf("81370f5125d0b1d408d4c3b232e6d25e795bebfb", "4c27967ad20c14b391e9601e41e604ad57c0222f"), roots.keys)
        for ((keyId, root) in roots) {
            assertEquals(keyId, GsmaCi.checkRoot(root, inTerm()))
            assertEquals(setOf("2.23.146.1.2.1.0"), Certificates.policies(root)) // id-rspRole-ci
        }
        assertNull(GsmaCi.checkRoot(roots.values.first(), date(2060, 1, 1)))
        // A self-signed root with an unknown key identifier is not used.
        assertNull(GsmaCi.checkRoot(ci, inTerm()))
        assertNotNull(Certificates.subjectKeyId(ci))
    }

    companion object {
        /** res/raw/gsma_ci_*.pem, as java_resources in the test jar or from the source tree. */
        fun shippedRoots(): Map<String, X509Certificate> {
            val factory = CertificateFactory.getInstance("X.509")
            return listOf("gsma_ci_rsp2_root_ci1.pem", "gsma_ci_oiste_g1.pem").associate { name ->
                val stream = TlsPolicyTest::class.java.classLoader!!.getResourceAsStream("res/raw/$name")
                    ?: File("res/raw/$name").takeIf { it.exists() }?.inputStream()
                    ?: throw AssertionError("missing res/raw/$name")
                val cert = stream.use { factory.generateCertificate(it) as X509Certificate }
                Hex.encode(Certificates.subjectKeyId(cert)!!) to cert
            }
        }
    }
}
