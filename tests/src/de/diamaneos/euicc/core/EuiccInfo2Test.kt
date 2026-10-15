// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class EuiccInfo2Test {
    private fun hex(s: String) = s.replace(" ", "").chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    // profileVersion 2.3.1, svn 2.2.2, euiccFirmwareVer 4.5.6, extCardResource, a constructed
    // CI key list, ppVersion 0.0.1.
    private val children = "81 03 02 03 01  82 03 02 02 02  83 03 04 05 06  84 03 01 02 03 " +
        "A9 16 04 14 " + "00".repeat(20) + " 04 03 00 00 01"

    @Test
    fun readsTheFirmwareVersion() {
        val body = hex(children)
        val data = hex("BF 22") + byteArrayOf(body.size.toByte()) + body
        assertEquals("4.5.6", EuiccInfo2.firmwareVersion(data))
    }

    @Test
    fun readsLongFormLengths() {
        val body = hex(children + " 84 81 90 " + "FF".repeat(0x90))
        val data = hex("BF 22 81") + byteArrayOf(body.size.toByte()) + body
        assertEquals("4.5.6", EuiccInfo2.firmwareVersion(data))
    }

    @Test
    fun missingOrMalformedGivesNull() {
        assertNull(EuiccInfo2.firmwareVersion(null))
        assertNull(EuiccInfo2.firmwareVersion(ByteArray(0)))
        assertNull(EuiccInfo2.firmwareVersion(hex("BF 22 05 81 03 02 03 01")))
        assertNull(EuiccInfo2.firmwareVersion(hex("BF 22 04 83 02 04 05")))
        assertNull(EuiccInfo2.firmwareVersion(hex("BF 20 05 83 03 04 05 06")))
        assertNull(EuiccInfo2.firmwareVersion(hex("BF 22 09 83 03 04")))
        assertNull(EuiccInfo2.firmwareVersion(hex("BF 22 80 83 03 04 05 06 00 00")))
    }

    @Test
    fun tlvReadsMultiByteTags() {
        val elements = Tlv.parse(hex("BF 22 00 5F 81 22 01 AA 83 00"))
        assertEquals(listOf(0xBF22, 0x5F8122, 0x83), elements.map { it.tag })
        assertEquals(1, elements[1].value.size)
    }

    @Test
    fun tlvRejectsBrokenInput() {
        for (input in listOf("BF", "83", "83 05 01", "83 84 00 00 00 01 00", "BF FF FF 22 00")) {
            assertThrows(IllegalArgumentException::class.java) { Tlv.parse(hex(input)) }
        }
    }
}
