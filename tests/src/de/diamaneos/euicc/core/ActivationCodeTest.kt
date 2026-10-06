// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class ActivationCodeTest {
    private fun problem(input: String) =
        assertThrows(ActivationCode.Invalid::class.java) { ActivationCode.parse(input) }.problem

    /** The examples of SGP.22 v2.5 section 4.1. */
    @Test
    fun parsesTheSpecificationExamples() {
        ActivationCode.parse("1\$SMDP.GSMA.COM\$04386-AGYFT-A74Y8-3F815").let {
            assertEquals("smdp.gsma.com", it.smdpAddress)
            assertEquals("04386-AGYFT-A74Y8-3F815", it.matchingId)
            assertNull(it.smdpOid)
            assertFalse(it.confirmationCodeRequired)
        }
        ActivationCode.parse("1\$SMDP.GSMA.COM\$04386-AGYFT-A74Y8-3F815\$\$1").let {
            assertNull(it.smdpOid)
            assertTrue(it.confirmationCodeRequired)
        }
        ActivationCode.parse("1\$SMDP.GSMA.COM\$04386-AGYFT-A74Y8-3F815\$1.3.6.1.4.1.31746\$1").let {
            assertEquals("1.3.6.1.4.1.31746", it.smdpOid)
            assertTrue(it.confirmationCodeRequired)
        }
        ActivationCode.parse("1\$SMDP.GSMA.COM\$04386-AGYFT-A74Y8-3F815\$1.3.6.1.4.1.31746").let {
            assertEquals("1.3.6.1.4.1.31746", it.smdpOid)
            assertFalse(it.confirmationCodeRequired)
        }
        ActivationCode.parse("1\$SMDP.GSMA.COM\$\$1.3.6.1.4.1.31746").let {
            assertEquals("", it.matchingId)
            assertEquals("1.3.6.1.4.1.31746", it.smdpOid)
        }
    }

    @Test
    fun acceptsTheQrPrefixWhitespaceAndLaterFields() {
        val code = ActivationCode.parse("  lpa:1\$rsp.example.com\$ABC-123\$\$1\$future\$fields \n")
        assertEquals("rsp.example.com", code.smdpAddress)
        assertEquals("ABC-123", code.matchingId)
        assertTrue(code.confirmationCodeRequired)
    }

    @Test
    fun refusesMalformedCodes() {
        assertEquals(ActivationCode.Problem.FORMAT, problem("1\$smdp.example.com"))
        assertEquals(ActivationCode.Problem.FORMAT, problem("LPA:"))
        assertEquals(ActivationCode.Problem.VERSION, problem("2\$smdp.example.com\$ABC"))
        assertEquals(ActivationCode.Problem.ADDRESS, problem("1\$\$ABC"))
        assertEquals(ActivationCode.Problem.ADDRESS, problem("1\$smdp.example.com:8443\$ABC"))
        assertEquals(ActivationCode.Problem.ADDRESS, problem("1\$192.0.2.1\$ABC"))
        assertEquals(ActivationCode.Problem.ADDRESS, problem("1\$localhost\$ABC"))
        assertEquals(ActivationCode.Problem.ADDRESS, problem("1\$smdp.example.com/path\$ABC"))
        assertEquals(ActivationCode.Problem.ADDRESS, problem("1\$smdp_x.example.com\$ABC"))
        assertEquals(ActivationCode.Problem.TOKEN, problem("1\$smdp.example.com\$ABC DEF"))
        assertEquals(ActivationCode.Problem.TOKEN, problem("1\$smdp.example.com\$ABC/../x"))
        assertEquals(ActivationCode.Problem.OID, problem("1\$smdp.example.com\$ABC\$3.1"))
        assertEquals(ActivationCode.Problem.OID, problem("1\$smdp.example.com\$ABC\$1.3.06"))
        assertEquals(ActivationCode.Problem.FLAG, problem("1\$smdp.example.com\$ABC\$\$yes"))
        assertEquals(ActivationCode.Problem.TOO_LONG, problem("1\$smdp.example.com\$" + "A".repeat(250)))
    }

    @Test
    fun encodesCanonically() {
        for (text in listOf(
            "1\$smdp.example.com\$ABC",
            "1\$smdp.example.com\$ABC\$\$1",
            "1\$smdp.example.com\$ABC\$1.2.3",
            "1\$smdp.example.com\$ABC\$1.2.3\$1",
        )) {
            assertEquals(text, ActivationCode.parse("LPA:$text").encoded())
        }
        assertEquals("1\$smdp.example.com\$ABC", ActivationCode.parse("1\$SMDP.Example.COM\$ABC\$\$0").encoded())
    }

    @Test
    fun neverPrintsTheMatchingId() {
        val code = ActivationCode.parse("1\$smdp.example.com\$SECRET-TOKEN")
        assertFalse(code.toString().contains("SECRET"))
        val invalid = assertThrows(ActivationCode.Invalid::class.java) { ActivationCode.parse("1\$smdp.example.com\$SECRET TOKEN") }
        assertFalse(invalid.message!!.contains("SECRET"))
    }

    @Test
    fun manualEntryAndEvents() {
        val manual = ActivationCode.fromParts(" RSP.Example.com ", " ABC-1 ")
        assertEquals("rsp.example.com", manual.smdpAddress)
        assertEquals("ABC-1", manual.matchingId)
        assertThrows(ActivationCode.Invalid::class.java) { ActivationCode.fromParts("rsp.example.com", "AB\$C") }
        assertThrows(ActivationCode.Invalid::class.java) { ActivationCode.fromParts("https://rsp.example.com", "ABC") }
        assertEquals("EVENT-1", ActivationCode.fromEvent("smdp.example.com", "EVENT-1")!!.matchingId)
        assertNull(ActivationCode.fromEvent("smdp.example.com", ""))
        assertNull(ActivationCode.fromEvent("not a host", "EVENT-1"))
    }

    @Test
    fun hostNames() {
        assertEquals("a.b.example", Fqdn.normalise("A.B.Example"))
        for (bad in listOf("", "example", "-a.example", "a-.example", "a..example", "a.example.", "a.123", "a b.example", "ä.example")) {
            assertNull(bad, Fqdn.normalise(bad))
        }
        assertTrue(Fqdn.matches("smdp.example.com", "SMDP.example.com"))
        assertTrue(Fqdn.matches("lpa.ds.gsma.com", "*.ds.gsma.com"))
        assertFalse(Fqdn.matches("ds.gsma.com", "*.ds.gsma.com"))
        assertFalse(Fqdn.matches("a.lpa.ds.gsma.com", "*.ds.gsma.com"))
        assertFalse(Fqdn.matches("smdp.example", "*.example"))
        assertFalse(Fqdn.matches("smdp.example.com", "s*.example.com"))
        assertFalse(Fqdn.matches("smdp.example.com", "smdp.example.org"))
    }

    @Test
    fun confirmationCodes() {
        assertEquals("1234", ConfirmationCode.normalise(" 1234 "))
        assertNull(ConfirmationCode.normalise(null))
        assertNull(ConfirmationCode.normalise(""))
        assertNull(ConfirmationCode.normalise("12 34"))
        assertNull(ConfirmationCode.normalise("1".repeat(33)))
        assertNull(ConfirmationCode.normalise("12ä4"))
    }

    /** SGP.22 3.1.3: SHA256(SHA256(CC) | TransactionID); expected value from Python's hashlib. */
    @Test
    fun hashesTheConfirmationCode() {
        val transactionId = ByteArray(16) { (it + 1).toByte() }
        assertArrayEquals(
            Hex.decode("94e57b8cdfe3eb0a8510f18898add0b1e67b48fafd39892796d6f65f9ce3cc40"),
            ConfirmationCode.hash("1234", transactionId),
        )
    }
}
