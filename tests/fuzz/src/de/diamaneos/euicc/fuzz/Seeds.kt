// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.fuzz

import de.diamaneos.euicc.core.Der
import de.diamaneos.euicc.core.Es9
import de.diamaneos.euicc.core.Json
import de.diamaneos.euicc.core.NotificationEvents
import de.diamaneos.euicc.core.Rsp
import de.diamaneos.euicc.core.TlsFixtures
import java.io.File

/**
 * Writes the seed corpus of every target to <dir>/<Target>/, built with the tests' encoder
 * (Rsp, Der, Json.write). Made-up values only. Run: Seeds <dir>.
 */
object Seeds {
    private val TXID = Rsp.TRANSACTION_ID

    /** The synthetic certificates only. The recorded server certificates are not used. */
    private val CERTS = listOf(
        TlsFixtures.TEST_CI, TlsFixtures.OTHER_CI, TlsFixtures.LEAF_DP, TlsFixtures.LEAF_DS, TlsFixtures.LEAF_NOPOLICY,
        TlsFixtures.LEAF_NOEKU, TlsFixtures.LEAF_CLIENTONLY, TlsFixtures.LEAF_FOREIGN, TlsFixtures.LEAF_EXPIRED,
    ).map { CertificateFuzz.pem(it) }

    private fun b64(b: ByteArray) = Es9.b64(b)
    private fun ok(vararg members: Pair<String, Any?>) = Json.write(
        mapOf("header" to mapOf("functionExecutionStatus" to mapOf("status" to "Executed-Success"))) + members.toMap()).toByteArray()

    private fun failed(subject: String, reason: String) = Json.write(mapOf("header" to mapOf("functionExecutionStatus" to
        mapOf("status" to "Failed", "statusCodeData" to mapOf("subjectCode" to subject, "reasonCode" to reason, "message" to "x"))))).toByteArray()

    private val metadatas: List<ByteArray> by lazy {
        listOf(
            Rsp.metadata(),
            Rsp.metadata(ppr = intArrayOf(1, 2), owner = true, profileClass = 0),
            Rsp.metadata(ppr = intArrayOf(2), owner = true),
            Rsp.metadata(profileClass = 1, notified = intArrayOf(0, 1, 2, 3)),
            Rsp.metadata(notified = intArrayOf(), iccid = null),
            Rsp.metadata(name = "\u0645\u0648\u0628\u0627\u064A\u0644 \u202Eabc", provider = "Ex\u200Bample\u2066"),
            Rsp.metadata(name = "a" + "\u0301".repeat(8) + "\uD83C\uDDE9\uD83C\uDDEA", provider = "\u3164\u2800"),
            // Two notification configuration entries.
            Der.tlv(0xBF25, Der.tlv(0x5A, Rsp.ICCID_A_BYTES), Der.utf8("P", 0x91), Der.utf8("N", 0x92), Der.int(2, 0x95),
                Der.tlv(0xB6, Der.tlv(0x30, Der.bits(4, 0, tag = 0x80), Der.utf8("a.example.com", 0x81)),
                    Der.tlv(0x30, Der.bits(4, 3, tag = 0x80), Der.utf8("b.example.com", 0x81))),
                Der.tlv(0xB7, Der.tlv(0x80, byteArrayOf(0x42, 0xF6.toByte(), 0x18)), Der.tlv(0x81, byteArrayOf(0x12)), Der.tlv(0x82, byteArrayOf(0x34))),
                Der.bits(3, 1, tag = 0x99), Der.tlv(0xBF22, Der.tlv(0x80, byteArrayOf(1))), Der.tlv(0xBF23, ByteArray(0))),
        )
    }

    private fun initiateBody(signed1: ByteArray = Rsp.serverSigned1(), cert: ByteArray = CERTS[2]) = ok(
        "transactionId" to Es9.hex(TXID), "serverSigned1" to b64(signed1),
        "serverSignature1" to b64(Der.tlv(0x5F37, ByteArray(64))), "euiccCiPKIdToBeUsed" to b64(Der.tlv(0x04, Rsp.CI1)),
        "serverCertificate" to b64(cert))

    private fun clientBody(metadata: ByteArray = Rsp.metadata(), cc: Boolean = false) = ok(
        "transactionId" to Es9.hex(TXID), "profileMetadata" to b64(metadata), "smdpSigned2" to b64(Rsp.smdpSigned2(cc)),
        "smdpSignature2" to b64(Der.tlv(0x5F37, ByteArray(64))), "smdpCertificate" to b64(CERTS[2]))

    private fun bppBody(bpp: ByteArray = Rsp.boundProfilePackage()) =
        ok("transactionId" to Es9.hex(TXID), "boundProfilePackage" to b64(bpp))

    private val eventsBody get() = ok("transactionId" to Es9.hex(TXID), "eventEntries" to listOf(
        mapOf("eventId" to "EVENT-1", "rspServerAddress" to "smdp.example.com"),
        mapOf("eventId" to "EVENT-2", "rspServerAddress" to "SMDP2.example.com")))

    private val es9Bodies: List<ByteArray> get() = listOf(
        initiateBody(), clientBody(), clientBody(Rsp.metadata(ppr = intArrayOf(1), owner = true), cc = true), bppBody(),
        eventsBody, ok(), failed("8.2.6", "3.8"), failed("8.1", "4.2"),
        Json.write(mapOf("header" to mapOf("functionExecutionStatus" to mapOf("status" to "Executed-WithWarning")),
            "transactionId" to "0A", "boundProfilePackage" to b64(Rsp.boundProfilePackage()))).toByteArray(),
    )

    private val cardResponses: List<ByteArray> get() = listOf(
        Rsp.installResult(), Rsp.installResult(errorReason = 10), Rsp.installResult(seq = 300, address = "b.example.com"),
        Rsp.otherNotification(1, NotificationEvents.ENABLE), Rsp.otherNotification(2, NotificationEvents.DISABLE),
        Rsp.otherNotification(3, NotificationEvents.DELETE, iccid = null), Rsp.authenticateServerOk(), Rsp.prepareDownloadOk(),
        Rsp.cancelSessionOk(), Rsp.euiccInfo1(),
        Der.tlv(0xBF22, Der.tlv(0x81, byteArrayOf(2, 3, 1)), Der.tlv(0x82, byteArrayOf(2, 2, 2)), Der.tlv(0x83, byteArrayOf(4, 5, 6)),
            Der.bits(5, 0, 4, tag = 0x88), Der.tlv(0xA9, Der.tlv(0x04, Rsp.CI1)), Der.tlv(0xAA, Der.tlv(0x04, Rsp.CI1)),
            Der.int(2, 0x8B), Der.tlv(0x04, byteArrayOf(0, 0, 1))),
        Der.tlv(0xBF38, Der.tlv(0xA1, Der.tlv(0x80, TXID), Der.int(7))),
    )

    fun all(): Map<String, List<ByteArray>> {
        val structures = cardResponses + metadatas + listOf(Rsp.serverSigned1(), Rsp.smdpSigned2(true), Rsp.boundProfilePackage()) +
            CERTS + listOf(Der.oid("2.23.146.1.2.1.3"), Der.int(-129), Der.bits(9, 0, 8), Der.utf8("\u00E9"))
        val codes = listOf(
            "LPA:1\$smdp.example.com\$MATCHING-1", "1\$SMDP.Example.com\$\$1.3.6.1.4.1.99999.1\$1", "1\$a.example\$X-1\$\$1",
            "LPA:1\$rsp.example.com\$ABC\$2.999.1\$0\$extra", "  lpa:1\$x.example.org\$  ", "1\$192.0.2.1\$X", "2\$a.example.com\$X",
        )
        return mapOf(
            "BerFuzz" to structures,
            "JsonFuzz" to es9Bodies + listOf("{\"a\":[1,-2.5e+3,true,false,null,\"\\u00e9\\ud83d\\ude00\"]}".toByteArray()),
            "Es9Fuzz" to es9Bodies,
            "ActivationCodeFuzz" to codes.map { Parts.join(it.toByteArray(), "MATCHING-1".toByteArray(), "CODE-1".toByteArray()) } +
                listOf(Parts.join("smdp.example.com".toByteArray(), " TOKEN ".toByteArray(), " Nick \u00E9".toByteArray())),
            "FqdnFuzz" to listOf("smdp.example.com" to "*.example.com", "a.rsp.example.com" to "*.rsp.example.com",
                "SMDP.EXAMPLE.COM" to "smdp.example.com", "x.example" to "*.example", "a-b.example.net" to "a-b.example.net")
                .map { (a, b) -> Parts.join(a.toByteArray(), b.toByteArray()) },
            "MetadataFuzz" to metadatas,
            "BppFuzz" to metadatas.map { Parts.join(it, Rsp.boundProfilePackage(it)) } +
                listOf(Parts.join(metadatas[1], Rsp.boundProfilePackage(metadatas[2])), Parts.join(metadatas[7], BppFuzz.packageOf(metadatas[7], 5))),
            "CardResponseFuzz" to cardResponses.map { Parts.join(it, TXID) },
            "ServerSignedFuzz" to listOf(Rsp.serverSigned1(), Rsp.serverSigned1(address = "SMDP.example.com"), Rsp.smdpSigned2(), Rsp.smdpSigned2(true),
                Der.tlv(0x30, Der.tlv(0x80, TXID), Der.bool(true), Der.tlv(0x5F49, ByteArray(65)))),
            "CertificateFuzz" to CERTS,
            "ServerTextFuzz" to listOf("Travel 5 GB", "a\u202E\u200Bb\n\nc", "\u0645\u0648 \u0301\u0301\u0301\u0301x", "\uD83C\uDDE9\uD83C\uDDEA \u3164\u2800")
                .map { byteArrayOf(64) + it.toByteArray(Charsets.UTF_16BE) },
            "DownloadFlowFuzz" to flowSeeds(),
        )
    }

    private fun flowSeeds(): List<ByteArray> {
        val e = ByteArray(0)
        val ppr = Rsp.metadata(ppr = intArrayOf(1, 2), owner = true)
        val events = Rsp.metadata(notified = intArrayOf(0, 1, 2, 3))
        return listOf(
            Parts.join(byteArrayOf(0, 0, 0, 0), initiateBody(), clientBody(), bppBody(), e, e),
            Parts.join(byteArrayOf(0, 4, 3, 0), initiateBody(), clientBody(cc = true), bppBody(), e, e),
            Parts.join(byteArrayOf(8, 0, 0, 0), initiateBody(), clientBody(ppr), bppBody(Rsp.boundProfilePackage(ppr)), e, e),
            Parts.join(byteArrayOf(0, 0, 0, 0), initiateBody(), clientBody(events), bppBody(Rsp.boundProfilePackage(Rsp.metadata())), Rsp.installResult(address = "b.example.com"), e),
            Parts.join(byteArrayOf(0, 1, 0, 0), initiateBody(), clientBody(), bppBody(), e, e),
            Parts.join(byteArrayOf(0, 2, 0, 0), initiateBody(), clientBody(), bppBody(), e, e),
            Parts.join(byteArrayOf(2, 0, 0, 0), initiateBody(Rsp.serverSigned1(address = "SMDP.EXAMPLE.COM")), clientBody(), bppBody(), Rsp.installResult(errorReason = 3), e),
        )
    }

    @JvmStatic
    fun main(args: Array<String>) {
        val dir = File(args.single())
        for ((target, seeds) in all()) {
            val d = File(dir, target).apply { mkdirs() }
            seeds.forEachIndexed { i, s -> File(d, "seed-%02d".format(i)).writeBytes(s) }
        }
    }
}
