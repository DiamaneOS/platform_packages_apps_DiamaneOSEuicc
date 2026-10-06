// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.core

/*
 * Synthetic SGP.22 data objects, built with the encodings of SGP.22 v2.5 (Annex H, AUTOMATIC
 * TAGS). Made-up values only: no real EID, ICCID, matching ID or key.
 */
object Rsp {
    val TRANSACTION_ID = ByteArray(16) { (0xA0 + it).toByte() }
    val CHALLENGE = ByteArray(16) { (0x10 + it).toByte() }
    val SERVER_CHALLENGE = ByteArray(16) { (0x30 + it).toByte() }

    /** GSMA RSP2 Root CI1 and a GSMA test CI, as an eUICC lists them. */
    val CI1 = Hex.decode("81370f5125d0b1d408d4c3b232e6d25e795bebfb")!!
    val TEST_CI = Hex.decode("f54172bdf98a95d65cbeb88a38a1c11d800a85c3")!!

    /** BCD with swapped nibbles of ICCID_A (Fixtures.kt), padded with F. */
    val ICCID_A_BYTES = Hex.decode("98940000000000000010")!!.let { it.copyOf().also { b -> b[9] = 0xF1.toByte() } }

    fun euiccInfo1(verify: List<ByteArray> = listOf(CI1, TEST_CI), sign: List<ByteArray> = listOf(CI1)) =
        Der.tlv(0xBF20,
            Der.tlv(0x82, byteArrayOf(2, 2, 2)),
            Der.tlv(0xA9, *verify.map { Der.tlv(0x04, it) }.toTypedArray()),
            Der.tlv(0xAA, *sign.map { Der.tlv(0x04, it) }.toTypedArray()))

    fun serverSigned1(
        transactionId: ByteArray = TRANSACTION_ID,
        challenge: ByteArray = CHALLENGE,
        address: String = "smdp.example.com",
    ) = Der.tlv(0x30,
        Der.tlv(0x80, transactionId),
        Der.tlv(0x81, challenge),
        Der.utf8(address, 0x83),
        Der.tlv(0x84, SERVER_CHALLENGE))

    fun initiateAuthentication(
        serverSigned1: ByteArray = serverSigned1(),
        ciToBeUsed: ByteArray = CI1,
        certificate: ByteArray = Der.tlv(0x30, byteArrayOf(0)),
    ) = Es9.InitiateAuthentication(TRANSACTION_ID, serverSigned1, Der.tlv(0x5F37, ByteArray(64)),
        Der.tlv(0x04, ciToBeUsed), certificate)

    /** AuthenticateServerResponse with authenticateResponseOk. */
    fun authenticateServerOk(transactionId: ByteArray = TRANSACTION_ID) = Der.tlv(0xBF38,
        Der.tlv(0xA0,
            Der.tlv(0x30, Der.tlv(0x80, transactionId), Der.utf8("smdp.example.com", 0x83), Der.tlv(0x84, SERVER_CHALLENGE)),
            Der.tlv(0x5F37, ByteArray(64)),
            Der.tlv(0x30, byteArrayOf(1)),
            Der.tlv(0x30, byteArrayOf(2))))

    fun prepareDownloadOk(transactionId: ByteArray = TRANSACTION_ID) = Der.tlv(0xBF21,
        Der.tlv(0xA0,
            Der.tlv(0x30, Der.tlv(0x80, transactionId), Der.tlv(0x5F49, ByteArray(65))),
            Der.tlv(0x5F37, ByteArray(64))))

    fun cancelSessionOk() = Der.tlv(0xBF41,
        Der.tlv(0xA0,
            Der.tlv(0x30, Der.tlv(0x80, TRANSACTION_ID), Der.oid("1.3.6.1.4.1.99999.1", 0x81), Der.int(1, 0x82)),
            Der.tlv(0x5F37, ByteArray(64))))

    fun smdpSigned2(ccRequired: Boolean = false, transactionId: ByteArray = TRANSACTION_ID) =
        Der.tlv(0x30, Der.tlv(0x80, transactionId), Der.bool(ccRequired))

    /** StoreMetadataRequest. [ppr] are PprIds bit numbers (1 = PPR1, 2 = PPR2). */
    fun metadata(
        provider: String = "Example Mobile",
        name: String = "Travel 5 GB",
        profileClass: Int? = null,
        ppr: IntArray = intArrayOf(),
        notified: IntArray = intArrayOf(0, 3),
        owner: Boolean = false,
    ): ByteArray {
        val parts = mutableListOf(
            Der.tlv(0x5A, ICCID_A_BYTES),
            Der.utf8(provider, 0x91),
            Der.utf8(name, 0x92),
        )
        if (profileClass != null) parts += Der.int(profileClass, 0x95)
        if (notified.isNotEmpty()) {
            parts += Der.tlv(0xB6, Der.tlv(0x30, Der.bits(4, *notified, tag = 0x80), Der.utf8("smdp.example.com", 0x81)))
        }
        if (owner) parts += Der.tlv(0xB7, Der.tlv(0x80, byteArrayOf(0x42, 0xF6.toByte(), 0x18)), Der.tlv(0x81, byteArrayOf(0x12)))
        if (ppr.isNotEmpty()) parts += Der.bits(3, *ppr, tag = 0x99)
        return Der.tlv(ProfileMetadata.TAG, *parts.toTypedArray())
    }

    fun authenticateClient(
        metadata: ByteArray = metadata(),
        signed2: ByteArray = smdpSigned2(),
        transactionId: ByteArray = TRANSACTION_ID,
    ) = Es9.AuthenticateClient(transactionId, metadata, signed2, Der.tlv(0x5F37, ByteArray(64)), Der.tlv(0x30, byteArrayOf(0)))

    /** A Bound Profile Package whose StoreMetadata is [metadata], split into two '88' segments with 8-byte MACs. */
    fun boundProfilePackage(metadata: ByteArray = metadata()): ByteArray {
        val half = metadata.size / 2
        val mac = ByteArray(8) { 0x77 }
        return Der.tlv(0xBF36,
            Der.tlv(0xBF23, Der.tlv(0x80, TRANSACTION_ID)),
            Der.tlv(0xA0, Der.tlv(0x87, ByteArray(20))),
            Der.tlv(0xA1, Der.tlv(0x88, metadata.copyOfRange(0, half) + mac), Der.tlv(0x88, metadata.copyOfRange(half, metadata.size) + mac)),
            Der.tlv(0xA3, Der.tlv(0x86, ByteArray(40))))
    }

    fun notificationMetadata(seq: Int, event: Int, address: String = "smdp.example.com", iccid: ByteArray? = ICCID_A_BYTES): ByteArray {
        val bit = Integer.numberOfTrailingZeros(event)
        val parts = mutableListOf(Der.int(seq, 0x80), Der.bits(4, bit, tag = 0x81), Der.utf8(address))
        if (iccid != null) parts += Der.tlv(0x5A, iccid)
        return Der.tlv(NotificationMetadata.TAG, *parts.toTypedArray())
    }

    /** ProfileInstallationResult; [errorReason] null for successResult. */
    fun installResult(seq: Int = 7, transactionId: ByteArray = TRANSACTION_ID, errorReason: Int? = null,
                      address: String = "smdp.example.com"): ByteArray {
        val final = if (errorReason == null) {
            Der.tlv(0xA0, Der.tlv(0x4F, ByteArray(16)), Der.tlv(0x04, byteArrayOf(0)))
        } else {
            Der.tlv(0xA1, Der.int(5, 0x80), Der.int(errorReason, 0x81))
        }
        return Der.tlv(InstallResult.TAG,
            Der.tlv(0xBF27,
                Der.tlv(0x80, transactionId),
                notificationMetadata(seq, NotificationEvents.INSTALL, address),
                Der.oid("1.3.6.1.4.1.99999.1"),
                Der.tlv(0xA2, final)),
            Der.tlv(0x5F37, ByteArray(64)))
    }

    /** OtherSignedNotification. */
    fun otherNotification(seq: Int, event: Int, address: String = "smdp.example.com", iccid: ByteArray? = ICCID_A_BYTES) =
        Der.tlv(0x30, notificationMetadata(seq, event, address, iccid), Der.tlv(0x5F37, ByteArray(64)),
            Der.tlv(0x30, byteArrayOf(1)), Der.tlv(0x30, byteArrayOf(2)))
}
