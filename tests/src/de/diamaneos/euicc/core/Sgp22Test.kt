// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class BerTest {
    private fun hex(s: String) = Hex.decode(s.replace(" ", ""))!!

    @Test
    fun encodesLengthsAndTags() {
        assertEquals("0400", Hex.encode(Der.tlv(0x04, ByteArray(0))))
        assertEquals("047f", Hex.encode(Der.tlv(0x04, ByteArray(0x7F))).substring(0, 4))
        assertEquals("048180", Hex.encode(Der.tlv(0x04, ByteArray(0x80))).substring(0, 6))
        assertEquals("04820100", Hex.encode(Der.tlv(0x04, ByteArray(0x100))).substring(0, 8))
        assertEquals("bf2000", Hex.encode(Der.tlv(0xBF20, ByteArray(0))))
        assertEquals("5f370100", Hex.encode(Der.tlv(0x5F37, byteArrayOf(0))))
        for (size in intArrayOf(0, 1, 0x7F, 0x80, 0xFF, 0x100, 0x10000)) {
            val element = Tlv.one(Der.tlv(0xBF36, ByteArray(size) { it.toByte() }))
            assertEquals(0xBF36, element.tag)
            assertEquals(size, element.value.size)
            assertTrue(element.constructed)
        }
    }

    @Test
    fun integersBooleansBitsAndStrings() {
        for (v in intArrayOf(0, 1, 127, 128, 255, 256, -1, -128, -129, 65535, Int.MAX_VALUE, Int.MIN_VALUE)) {
            assertEquals(v, Tlv.one(Der.int(v)).int())
        }
        assertEquals("020100", Hex.encode(Der.int(0)))
        assertEquals("02020080", Hex.encode(Der.int(128)))
        assertEquals("0201ff", Hex.encode(Der.int(-1)))
        assertTrue(Tlv.one(hex("01 01 ff")).bool())
        assertFalse(Tlv.one(hex("01 01 00")).bool())
        assertThrows(IllegalArgumentException::class.java) { Tlv.one(hex("01 02 00 00")).bool() }
        // NotificationEvent {install(0), enable(1), disable(2), delete(3)}: delete only.
        val bits = Tlv.one(hex("03 02 04 10")).bits()
        assertEquals(4, bits.size)
        assertTrue(bits[3])
        assertFalse(bits[0])
        assertEquals(8, bits.toFlags())
        assertThrows(IllegalArgumentException::class.java) { Tlv.one(hex("03 01 08")).bits() }
        assertEquals("smdp.example.com", Tlv.one(Der.utf8("smdp.example.com")).utf8())
        assertThrows(IllegalArgumentException::class.java) { Tlv.one(hex("0c 02 c3 28")).utf8() }
    }

    /** Annex H role OIDs and the X.690 8.19 examples. */
    @Test
    fun objectIdentifiers() {
        assertEquals("0607678112010201 03".replace(" ", ""), Hex.encode(Der.oid("2.23.146.1.2.1.3")))
        assertEquals("2.23.146.1.2.1.3", Tlv.one(hex("06 07 67 81 12 01 02 01 03")).oid())
        assertEquals("1.2.840.10045.3.1.7", Tlv.one(hex("06 08 2a 86 48 ce 3d 03 01 07")).oid())
        assertEquals("2.999.3", Tlv.one(Der.oid("2.999.3")).oid())
        assertThrows(IllegalArgumentException::class.java) { Tlv.one(hex("06 02 80 01")).oid() }
        assertThrows(IllegalArgumentException::class.java) { Tlv.one(hex("06 01 81")).oid() }
    }

    @Test
    fun rejectsBrokenTlvs() {
        for (input in listOf("BF", "83", "83 05 01", "83 84 00 00 00 01 00", "BF FF FF 22 00", "04 80 00 00")) {
            assertThrows(IllegalArgumentException::class.java) { Tlv.parse(hex(input)) }
        }
        assertThrows(IllegalArgumentException::class.java) { Tlv.one(hex("04 00 04 00")) }
        assertThrows(IllegalArgumentException::class.java) { Tlv.one(hex("04 00"), 0x30) }
    }

    @Test
    fun iccids() {
        assertEquals(ICCID_A, Iccid.decode(Rsp.ICCID_A_BYTES))
        assertEquals("89012345678901234567", Iccid.decode(hex("98 10 32 54 76 98 10 32 54 76")))
        assertNull(Iccid.decode(hex("98 10 32 54 76 98 10 32 F4 76"))) // digit after filler
        assertNull(Iccid.decode(hex("98 1A 32 54 76 98 10 32 54 76"))) // not a digit
        assertNull(Iccid.decode(hex("98 10 32")))
    }
}

class Sgp22Test {
    @Test
    fun euiccInfo1() {
        val info = EuiccInfo1.parse(Rsp.euiccInfo1())
        assertEquals(Version(2, 2, 2), info.svn)
        assertEquals(2, info.ciForVerification.size)
        assertArrayEquals(Rsp.CI1, info.ciForVerification[0])
        assertArrayEquals(Rsp.CI1, info.ciForSigning.single())
        assertThrows(IllegalArgumentException::class.java) { EuiccInfo1.parse(Der.tlv(0xBF20, Der.tlv(0x82, byteArrayOf(2, 2)))) }
        assertThrows(IllegalArgumentException::class.java) { EuiccInfo1.parse(Der.tlv(0xBF22, ByteArray(0))) }
    }

    @Test
    fun euiccInfo2Summary() {
        val info2 = Der.tlv(0xBF22,
            Der.tlv(0x81, byteArrayOf(2, 3, 1)), Der.tlv(0x82, byteArrayOf(2, 2, 2)), Der.tlv(0x83, byteArrayOf(4, 5, 6)),
            Der.tlv(0x84, byteArrayOf(1)), Der.tlv(0x85, byteArrayOf(0)),
            Der.bits(5, 0, 4, tag = 0x88),
            Der.tlv(0xA9, Der.tlv(0x04, Rsp.CI1)), Der.tlv(0xAA, Der.tlv(0x04, Rsp.CI1)),
            Der.int(2, 0x8B), Der.tlv(0x04, byteArrayOf(0, 0, 1)), Der.utf8("", 0x0C))
        val summary = EuiccInfo2.summary(info2)!!
        assertEquals(Version(2, 2, 2), summary.svn)
        assertEquals(Version(2, 3, 1), summary.profileVersion)
        assertEquals("4.5.6", EuiccInfo2.firmwareVersion(info2))
        assertEquals(listOf("additionalProfile", "deviceInfoExtensibilitySupport"), summary.rspCapabilities)
        assertEquals(2, summary.category)
        assertEquals(Version(0, 0, 1), summary.ppVersion)
        assertEquals("GSMA RSP2 Root CI1", GsmaCi.describe(summary.ciForVerification.single()))
        assertEquals("unknown CI 010203", GsmaCi.describe(byteArrayOf(1, 2, 3, 4)))
    }

    @Test
    fun serverSigned1() {
        val signed = ServerSigned1.parse(Rsp.serverSigned1())
        assertArrayEquals(Rsp.TRANSACTION_ID, signed.transactionId)
        assertArrayEquals(Rsp.CHALLENGE, signed.euiccChallenge)
        assertEquals("smdp.example.com", signed.serverAddress)
        assertThrows(IllegalArgumentException::class.java) { ServerSigned1.parse(Rsp.serverSigned1(challenge = ByteArray(8))) }
        assertThrows(IllegalArgumentException::class.java) { ServerSigned1.parse(Rsp.serverSigned1(transactionId = ByteArray(17))) }
    }

    @Test
    fun smdpSigned2() {
        assertTrue(SmdpSigned2.parse(Rsp.smdpSigned2(ccRequired = true)).ccRequired)
        assertFalse(SmdpSigned2.parse(Rsp.smdpSigned2()).ccRequired)
        // With bppEuiccOtpk.
        val withOtpk = Der.tlv(0x30, Der.tlv(0x80, Rsp.TRANSACTION_ID), Der.bool(true), Der.tlv(0x5F49, ByteArray(65)))
        assertTrue(SmdpSigned2.parse(withOtpk).ccRequired)
    }

    @Test
    fun profileMetadata() {
        val m = ProfileMetadata.parse(Rsp.metadata(ppr = intArrayOf(1, 2), owner = true, profileClass = 0))
        assertEquals(ICCID_A, m.iccid)
        assertEquals("Example Mobile", m.serviceProviderName)
        assertEquals("Travel 5 GB", m.profileName)
        assertEquals(ProfileMetadata.CLASS_TEST, m.profileClass)
        assertTrue(m.ppr1)
        assertTrue(m.ppr2)
        assertEquals(3, m.policyRules)
        assertArrayEquals(byteArrayOf(0x42, 0xF6.toByte(), 0x18), m.owner!!.mccMnc)
        assertEquals(NotificationEvents.INSTALL or NotificationEvents.DELETE, m.notifiedEvents)
        assertFalse(m.toString().contains(ICCID_A))
        val plain = ProfileMetadata.parse(Rsp.metadata(notified = intArrayOf()))
        assertEquals(ProfileMetadata.CLASS_OPERATIONAL, plain.profileClass)
        assertEquals(0, plain.policyRules)
        assertNull(plain.owner)
        assertThrows(IllegalArgumentException::class.java) { ProfileMetadata.parse(Rsp.metadata(name = "x".repeat(65))) }
    }

    @Test
    fun metadataInsideTheBoundProfilePackage() {
        val bpp = Rsp.boundProfilePackage(Rsp.metadata(ppr = intArrayOf(2)))
        val m = ProfileMetadata.fromBoundProfilePackage(bpp)!!
        assertEquals("Travel 5 GB", m.profileName)
        assertEquals(2, m.policyRules)
        assertNull(ProfileMetadata.fromBoundProfilePackage(Der.tlv(0xBF36, Der.tlv(0xA3, ByteArray(0)))))
        assertNull(ProfileMetadata.fromBoundProfilePackage(byteArrayOf(1, 2, 3)))
    }

    @Test
    fun installResults() {
        val ok = PendingNotification.parse(Rsp.installResult())
        assertTrue(ok.install!!.success)
        assertArrayEquals(Rsp.TRANSACTION_ID, ok.install!!.transactionId)
        assertEquals(7, ok.metadata.seq)
        assertEquals(NotificationEvents.INSTALL, ok.metadata.event)
        assertEquals("smdp.example.com", ok.metadata.address)
        assertEquals(ICCID_A, ok.metadata.iccid)
        assertEquals("1.3.6.1.4.1.99999.1", ok.install!!.smdpOid)
        val error = PendingNotification.parse(Rsp.installResult(errorReason = 10)).install!!
        assertFalse(error.success)
        assertEquals(5, error.bppCommandId)
        assertEquals(10, error.errorReason)
    }

    @Test
    fun otherNotifications() {
        val n = PendingNotification.parse(Rsp.otherNotification(12, NotificationEvents.DISABLE))
        assertNull(n.install)
        assertEquals(12, n.metadata.seq)
        assertEquals(NotificationEvents.DISABLE, n.metadata.event)
        assertNull(PendingNotification.parse(Rsp.otherNotification(1, NotificationEvents.ENABLE, iccid = null)).metadata.iccid)
        assertNull(PendingNotification.parseOrNull(byteArrayOf(0x30, 0x00)))
        assertNull(PendingNotification.parseOrNull(null))
        // Two events at once is not a notification.
        val twoBits = Der.tlv(0x30, Der.tlv(NotificationMetadata.TAG, Der.int(1, 0x80), Der.bits(4, 1, 2, tag = 0x81), Der.utf8("a.example")))
        assertNull(PendingNotification.parseOrNull(twoBits))
    }

    @Test
    fun cardResponses() {
        assertTrue(CardResponses.authenticateServerOk(Rsp.authenticateServerOk(), Rsp.TRANSACTION_ID))
        assertFalse(CardResponses.authenticateServerOk(Rsp.authenticateServerOk(ByteArray(16)), Rsp.TRANSACTION_ID))
        val error = Der.tlv(0xBF38, Der.tlv(0xA1, Der.tlv(0x80, Rsp.TRANSACTION_ID), Der.int(7)))
        assertFalse(CardResponses.authenticateServerOk(error, Rsp.TRANSACTION_ID))
        assertTrue(CardResponses.prepareDownloadOk(Rsp.prepareDownloadOk(), Rsp.TRANSACTION_ID))
        assertFalse(CardResponses.prepareDownloadOk(Der.tlv(0xBF21, Der.tlv(0xA1, Der.tlv(0x80, Rsp.TRANSACTION_ID), Der.int(2))), Rsp.TRANSACTION_ID))
        assertTrue(CardResponses.cancelSessionOk(Rsp.cancelSessionOk()))
        assertFalse(CardResponses.cancelSessionOk(Der.tlv(0xBF41, Der.int(5, 0x81))))
        assertFalse(CardResponses.cancelSessionOk(byteArrayOf(1)))
    }

    @Test
    fun ownedSetHashesWithItsSalt() {
        val salt = ByteArray(32) { it.toByte() }
        val set = OwnedSet(salt, emptyList())
        // SHA-256(salt | ICCID), expected value from Python's hashlib.
        assertEquals("f6da46fe55afc434dc8888a938c263d7000cfd5c2b0037823d443ad7518de882", set.key(ICCID_A))
        set.add(ICCID_A)
        assertTrue(ICCID_A in set)
        assertFalse(ICCID_B in set)
        assertFalse(set.snapshot().any { it.contains(ICCID_A) })
        assertFalse(ICCID_A in OwnedSet(ByteArray(32), set.snapshot()))
        set.remove(ICCID_A)
        assertEquals(0, set.size)
        repeat(OwnedSet.MAX + 5) { set.add("89490000000000%05d".format(it)) }
        assertEquals(OwnedSet.MAX, set.size)
        assertFalse("8949000000000000000" in set)
        assertNotNull(assertThrows(IllegalArgumentException::class.java) { OwnedSet(ByteArray(8), emptyList()) })
    }
}
