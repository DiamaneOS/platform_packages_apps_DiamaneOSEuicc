// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.core

import java.io.ByteArrayInputStream
import java.util.Base64
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class JsonTest {
    private fun rejects(text: String, limits: JsonLimits = JsonLimits()) {
        assertThrows(text, JsonException::class.java) { Json.parse(text, limits) }
    }

    @Test
    fun parsesValidJson() {
        val v = Json.parse(" {\"a\" : \"x\\u00e9\\n\\\"\", \"b\":[1, -2.5e3, true, false, null, {}], \"c\":{\"d\":\"\\ud83d\\ude00\"}} ") as JsonObject
        assertEquals("xé\n\"", v.string("a"))
        assertEquals(6, v.array("b")!!.items.size)
        assertEquals("-2.5e3", (v.array("b")!!.items[1] as JsonNumber).text)
        assertEquals("\uD83D\uDE00", v.obj("c")!!.string("d"))
        assertEquals("é", (Json.parse("\"é\"".toByteArray(Charsets.UTF_8)) as JsonString).value)
    }

    @Test
    fun rejectsWhatIsNotStrictJson() {
        for (text in listOf(
            "", "{", "{}}", "{} {}", "{\"a\":1,}", "[1,]", "{'a':1}", "{a:1}", "{\"a\":1 // c\n}",
            "/* c */ {}", "{\"a\":01}", "{\"a\":1.}", "{\"a\":.5}", "{\"a\":+1}", "{\"a\":NaN}",
            "{\"a\":tru}", "{\"a\":\"\t\"}", "{\"a\":\"\\x\"}", "{\"a\":\"\\ud800\"}", "{\"a\":\"\\udc00x\"}",
            "{\"a\":1,\"a\":2}", "\uFEFF{}", "{\"a\":\"unterminated}",
        )) {
            rejects(text)
        }
        assertThrows(JsonException::class.java) { Json.parse(byteArrayOf(0x7B, 0x22, 0xC3.toByte(), 0x28, 0x22, 0x3A, 0x31, 0x7D)) }
        assertThrows(JsonException::class.java) { Json.parseObject("[]".toByteArray()) }
    }

    @Test
    fun enforcesLimits() {
        val limits = JsonLimits(maxDepth = 3, maxStringChars = 8, maxMembers = 2, maxItems = 3)
        Json.parse("{\"a\":{\"b\":{\"c\":1}}}", limits)
        rejects("{\"a\":{\"b\":{\"c\":{\"d\":1}}}}", limits)
        rejects("{\"a\":\"123456789\"}", limits)
        rejects("{\"a\":1,\"b\":2,\"c\":3}", limits)
        rejects("[1,2,3,4]", limits)
        rejects("{\"a\":1" + "0".repeat(40) + "}")
    }

    @Test
    fun writesOnlyTheRequiredEscapes() {
        assertEquals(
            "{\"a\":\"q\\\"b\\\\s/\\n\\u0001é\",\"n\":{\"x\":[1,true]}}",
            Json.write(mapOf("a" to "q\"b\\s/\n\u0001é", "n" to mapOf("x" to listOf(1, true)))),
        )
    }

    /** SGP.22 v2.5 Annex I: the ES2+ DownloadOrder request lacks a comma, so it is not JSON. */
    @Test
    fun annexIExamples() {
        val response = """
            {
            	"header" : {
            		"functionExecutionStatus" : {
            			"status" : "Failed",
            			"statusCodeData" : {
            				"subjectCode" : "8.2.5",
            				"reasonCode" : "3.7",
            				"message" : "No more Profile"
            			}
            		}
            	}
            }
        """.trimIndent()
        val e = assertThrows(RspException::class.java) { Es9.checkStatus(Json.parse(response) as JsonObject) }
        assertEquals(Failure.SERVER_REFUSED, e.failure)
        assertEquals("8.2.5", e.subjectCode)
        assertEquals("3.7", e.reasonCode)
        rejects("""
            {
            	"header" : {
            		"functionRequesterIdentifier" : "RequesterID",
            		"functionCallIdentifier" : "TX-567"
            	}
            	"eid" : "01020300405060708090A0B0C0D0EOF",
            	"iccid" : "01234567890123456789",
            	"profileType" : "myProfileType"
            }
        """.trimIndent())
    }
}

class Es9Test {
    private fun b64(bytes: ByteArray) = Base64.getEncoder().encodeToString(bytes)

    private fun success(vararg members: Pair<String, Any?>): JsonObject =
        Json.parse(Json.write(mapOf("header" to mapOf("functionExecutionStatus" to mapOf("status" to "Executed-Success"))) + members.toMap())) as JsonObject

    @Test
    fun requestBodies() {
        assertEquals(
            "{\"euiccChallenge\":\"AQI=\",\"euiccInfo1\":\"vyAA\",\"smdpAddress\":\"smdp.example.com\"}",
            Es9.initiateAuthenticationRequest(byteArrayOf(1, 2), Der.tlv(0xBF20, ByteArray(0)), "smdp.example.com"),
        )
        assertEquals(
            "{\"transactionId\":\"0A0B\",\"authenticateServerResponse\":\"vzgA\"}",
            Es9.authenticateClientRequest(byteArrayOf(10, 11), Der.tlv(0xBF38, ByteArray(0))),
        )
        assertEquals("{\"pendingNotification\":\"MAA=\"}", Es9.handleNotificationRequest(byteArrayOf(0x30, 0)))
        assertEquals(
            "{\"transactionId\":\"FF\",\"cancelSessionResponse\":\"v0EA\"}",
            Es9.cancelSessionRequest(byteArrayOf(-1), Der.tlv(0xBF41, ByteArray(0))),
        )
    }

    @Test
    fun parsesInitiateAuthentication() {
        val signed1 = Rsp.serverSigned1()
        val body = success(
            "transactionId" to Es9.hex(Rsp.TRANSACTION_ID),
            "serverSigned1" to b64(signed1),
            "serverSignature1" to b64(Der.tlv(0x5F37, ByteArray(64))),
            "euiccCiPKIdToBeUsed" to b64(Der.tlv(0x04, Rsp.CI1)),
            "serverCertificate" to b64(Der.tlv(0x30, byteArrayOf(0))),
            "unknownField" to "ignored",
        )
        val result = Es9.parseInitiateAuthentication(body)
        assertArrayEquals(Rsp.TRANSACTION_ID, result.transactionId)
        assertArrayEquals(signed1, result.serverSigned1)
        // Annex I's spelling of the CI field works too.
        val annex = success(
            "transactionId" to "0123456789ABCDEF",
            "serverSigned1" to b64(signed1),
            "serverSignature1" to b64(Der.tlv(0x5F37, ByteArray(64))),
            "euiccCiPKIdTobeUsed" to b64(Der.tlv(0x04, Rsp.CI1)),
            "serverCertificate" to b64(Der.tlv(0x30, byteArrayOf(0))),
        )
        assertArrayEquals(Der.tlv(0x04, Rsp.CI1), Es9.parseInitiateAuthentication(annex).euiccCiPkIdToBeUsed)
    }

    @Test
    fun rejectsBadFields() {
        fun ia(vararg replace: Pair<String, Any?>): JsonObject {
            val members = mutableMapOf<String, Any?>(
                "transactionId" to Es9.hex(Rsp.TRANSACTION_ID),
                "serverSigned1" to b64(Rsp.serverSigned1()),
                "serverSignature1" to b64(Der.tlv(0x5F37, ByteArray(64))),
                "euiccCiPKIdToBeUsed" to b64(Der.tlv(0x04, Rsp.CI1)),
                "serverCertificate" to b64(Der.tlv(0x30, byteArrayOf(0))),
            )
            replace.forEach { (k, v) -> if (v == null) members.remove(k) else members[k] = v }
            return success(*members.toList().toTypedArray())
        }
        for (bad in listOf(
            "transactionId" to "XYZ", "transactionId" to "ABC", "transactionId" to "A".repeat(34),
            "serverSigned1" to "not base64!", "serverSigned1" to b64(Der.tlv(0x31, ByteArray(0))),
            "serverSigned1" to b64(Rsp.serverSigned1() + byteArrayOf(0)), "serverSignature1" to b64(Der.tlv(0x04, ByteArray(1))),
            "serverCertificate" to null, "euiccCiPKIdToBeUsed" to "MDM=",
        )) {
            val e = assertThrows(bad.toString(), RspException::class.java) { Es9.parseInitiateAuthentication(ia(bad)) }
            assertEquals(Failure.INVALID_RESPONSE, e.failure)
        }
        assertThrows(RspException::class.java) { Es9.parseInitiateAuthentication(Json.parse("{\"transactionId\":\"00\"}") as JsonObject) }
    }

    @Test
    fun statusCodes() {
        fun status(status: String, subject: String? = null) = Json.parse(Json.write(mapOf("header" to mapOf(
            "functionExecutionStatus" to mapOf("status" to status,
                "statusCodeData" to mapOf("subjectCode" to subject, "reasonCode" to "3.8")))))) as JsonObject
        Es9.checkStatus(status("Executed-WithWarning"))
        assertEquals("8.2.6", assertThrows(RspException::class.java) { Es9.checkStatus(status("Failed", "8.2.6")) }.subjectCode)
        assertEquals(Failure.SERVER_REFUSED, assertThrows(RspException::class.java) { Es9.checkStatus(status("Expired", "8.8.5")) }.failure)
        // Codes that are not status codes are dropped, not shown.
        assertNull(assertThrows(RspException::class.java) { Es9.checkStatus(status("Failed", "<b>")) }.subjectCode)
        assertEquals(Failure.INVALID_RESPONSE, assertThrows(RspException::class.java) { Es9.checkStatus(status("Done")) }.failure)
        assertEquals(Failure.INVALID_RESPONSE, assertThrows(RspException::class.java) { Es9.checkStatus(JsonObject(emptyMap())) }.failure)
    }

    @Test
    fun boundProfilePackageAndEvents() {
        val bpp = Rsp.boundProfilePackage()
        val (transactionId, parsed) = Es9.parseBoundProfilePackage(success(
            "transactionId" to Es9.hex(Rsp.TRANSACTION_ID), "boundProfilePackage" to b64(bpp)))
        assertArrayEquals(Rsp.TRANSACTION_ID, transactionId)
        assertArrayEquals(bpp, parsed)
        val big = Der.tlv(0xBF36, ByteArray(Es9.MAX_BPP_BYTES + 1))
        val header = success("transactionId" to "00")
        val tooBig = JsonObject(header.members + ("boundProfilePackage" to JsonString(b64(big))))
        assertEquals(Failure.INVALID_RESPONSE, assertThrows(RspException::class.java) { Es9.parseBoundProfilePackage(tooBig) }.failure)
        // The response limit stops a larger body before it is parsed.
        assertThrows(JsonException::class.java) { Json.parse("\"" + "A".repeat(Es9.MAX_BPP_RESPONSE_BYTES + 1) + "\"", Es9.BPP_LIMITS) }
        val events = Es9.parseEventEntries(success(
            "transactionId" to "00",
            "eventEntries" to listOf(
                mapOf("eventId" to "EVENT-1", "rspServerAddress" to "SMDP.example.com"),
                mapOf("eventId" to "bad id", "rspServerAddress" to "smdp.example.com"),
                mapOf("eventId" to "EVENT-2", "rspServerAddress" to "http://smdp.example.com"),
                mapOf("eventId" to "EVENT-3"),
            )))
        assertEquals(1, events.size)
        assertEquals("smdp.example.com", events[0].rspServerAddress)
        assertEquals("EVENT-1", events[0].eventId)
    }

    @Test
    fun httpRules() {
        HttpRules.checkJsonResponse(200, "application/json;charset=UTF-8", -1, 100)
        HttpRules.checkJsonResponse(200, "Application/JSON", 100, 100)
        for ((status, type, length) in listOf(Triple(302, "application/json", -1L), Triple(204, "application/json", -1L),
            Triple(500, "application/json", -1L), Triple(200, "text/html", -1L), Triple(200, null, -1L), Triple(200, "application/json", 101L))) {
            assertThrows(RspException::class.java) { HttpRules.checkJsonResponse(status, type, length, 100) }
        }
        HttpRules.checkNotificationResponse(204)
        assertEquals(Failure.HTTP_STATUS, assertThrows(RspException::class.java) { HttpRules.checkNotificationResponse(301) }.failure)
        assertEquals(100, HttpRules.readBounded(ByteArrayInputStream(ByteArray(100)), 100).size)
        assertEquals(Failure.INVALID_RESPONSE,
            assertThrows(RspException::class.java) { HttpRules.readBounded(ByteArrayInputStream(ByteArray(101)), 100) }.failure)
    }

    /** EuiccManager's OPERATION_SMDX_SUBJECT_REASON_CODE, as EuiccController decodes it. */
    @Test
    fun smdxCodes() {
        val code = Results.smdxCode("8.2.6", "3.8")!!
        assertEquals(Results.OPERATION_SMDX_SUBJECT_REASON_CODE, code ushr 24)
        assertEquals(0x826038, code and 0xFFFFFF)
        assertNull(Results.smdxCode("8.2.16", "1"))
        assertNull(Results.smdxCode("1.2.3.4", "1"))
        assertNull(Results.smdxCode(null, "1"))
        assertEquals(Results.OK, Results.fromOutcome(Outcome.Checked("x", Version(2, 2, 2))))
        assertEquals(Results.error(Results.OPERATION_HTTP, Results.ERROR_CONNECTION_ERROR),
            Results.fromOutcome(Outcome.Failed(RspException(Failure.NETWORK))))
        assertEquals(Results.error(Results.OPERATION_EUICC_GSMA, 6),
            Results.fromOutcome(Outcome.Failed(RspException(Failure.CARD_REFUSED_SERVER, cardCode = 6))))
    }
}
