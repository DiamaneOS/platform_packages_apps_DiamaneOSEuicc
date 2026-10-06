// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.core

/*
 * SGP.22 v2 data objects the download reads (GSMA SGP.22 v2.5, sections 2.5.4, 2.5.6, 5.5.3,
 * 5.7.6 to 5.7.14 and the ASN.1 module). The RSP module uses AUTOMATIC TAGS, so untagged
 * components of an all-untagged SEQUENCE or CHOICE get context tags [0], [1], ...
 * Parsers throw IllegalArgumentException on malformed input. toString() never prints an ICCID,
 * transaction ID or challenge.
 */

/** NotificationEvent bits, with the values of EuiccNotification.EVENT_*. */
object NotificationEvents {
    const val INSTALL = 1
    const val ENABLE = 1 shl 1
    const val DISABLE = 1 shl 2
    const val DELETE = 1 shl 3
    const val ALL = INSTALL or ENABLE or DISABLE or DELETE
}

/** ServerSigned1 (5.7.13): what the RSP server signed in InitiateAuthentication. */
class ServerSigned1(
    val transactionId: ByteArray,
    val euiccChallenge: ByteArray,
    val serverAddress: String,
    val serverChallenge: ByteArray,
) {
    override fun toString() = "ServerSigned1"

    companion object {
        fun parse(data: ByteArray): ServerSigned1 {
            val seq = Tlv.one(data, 0x30)
            val transactionId = seq.require(0x80).value
            require(transactionId.size in 1..16) { "bad transaction ID" }
            val challenge = seq.require(0x81).value
            require(challenge.size == 16) { "bad challenge" }
            val serverChallenge = seq.require(0x84).value
            require(serverChallenge.size == 16) { "bad challenge" }
            return ServerSigned1(transactionId, challenge, seq.require(0x83).utf8(), serverChallenge)
        }
    }
}

/** SmdpSigned2 (5.7.5): the transaction ID and whether a confirmation code is required. */
class SmdpSigned2(val transactionId: ByteArray, val ccRequired: Boolean) {
    override fun toString() = "SmdpSigned2(ccRequired=$ccRequired)"

    companion object {
        fun parse(data: ByteArray): SmdpSigned2 {
            val seq = Tlv.one(data, 0x30)
            return SmdpSigned2(seq.require(0x80).value, seq.require(0x01).bool())
        }
    }
}

/** OperatorId (2.9.2, "Data type: OperatorId"): the Profile Owner, as the RAT compares it. */
class OperatorId(val mccMnc: ByteArray, val gid1: ByteArray?, val gid2: ByteArray?) {
    override fun toString() = "OperatorId"
}

/**
 * StoreMetadataRequest (5.5.3), the Profile Metadata of ES9+.AuthenticateClient and of the
 * Bound Profile Package. [iccid] is used only to remember which profiles this app installed.
 */
class ProfileMetadata(
    val iccid: String?,
    val serviceProviderName: String,
    val profileName: String,
    val profileClass: Int,
    /** PprIds: bit 1 PPR1 (no disabling), bit 2 PPR2 (no deletion). */
    val ppr: Int,
    val owner: OperatorId?,
    /** NotificationEvent bits of every Notification Configuration Information entry. */
    val notifiedEvents: Int,
) {
    val ppr1: Boolean get() = ppr and PPR1 != 0
    val ppr2: Boolean get() = ppr and PPR2 != 0

    /** The rules as EuiccProfileInfo.POLICY_RULE_* bits (DO_NOT_DISABLE 1, DO_NOT_DELETE 2). */
    val policyRules: Int get() = (if (ppr1) 1 else 0) or (if (ppr2) 2 else 0)

    override fun toString() = "ProfileMetadata(class=$profileClass, ppr=$ppr, notified=$notifiedEvents)"

    companion object {
        const val TAG = 0xBF25
        const val PPR1 = 1 shl 1
        const val PPR2 = 1 shl 2
        const val CLASS_TEST = 0
        const val CLASS_PROVISIONING = 1
        const val CLASS_OPERATIONAL = 2

        fun parse(data: ByteArray): ProfileMetadata = parse(Tlv.one(data, TAG))

        fun parse(element: Tlv): ProfileMetadata {
            require(element.tag == TAG) { "unexpected tag" }
            val children = element.children()
            fun child(tag: Int) = children.firstOrNull { it.tag == tag }
            val name = child(0x92)?.utf8().orEmpty()
            val provider = child(0x91)?.utf8().orEmpty()
            require(name.length <= 64 && provider.length <= 32) { "name too long" }
            var events = 0
            child(0xB6)?.children()?.forEach { entry ->
                require(entry.tag == 0x30) { "bad notification configuration" }
                events = events or entry.require(0x80).bits().toFlags()
            }
            val owner = child(0xB7)?.let { o ->
                val mccMnc = o.require(0x80).value
                require(mccMnc.size == 3) { "bad MCC/MNC" }
                OperatorId(mccMnc, o.child(0x81)?.value, o.child(0x82)?.value)
            }
            return ProfileMetadata(
                iccid = child(0x5A)?.value?.let { Iccid.decode(it) },
                serviceProviderName = provider,
                profileName = name,
                profileClass = child(0x95)?.int() ?: CLASS_OPERATIONAL,
                ppr = child(0x99)?.bits()?.toFlags() ?: 0,
                owner = owner,
                notifiedEvents = events and NotificationEvents.ALL,
            )
        }

        /**
         * The StoreMetadataRequest inside a Bound Profile Package (2.5.4): the '88' segments of
         * sequenceOf88 are MAC protected only, so their contents without the 8-byte C-MAC
         * concatenate to it. Null if the package does not have that shape.
         */
        fun fromBoundProfilePackage(bpp: ByteArray): ProfileMetadata? = try {
            val sequence = Tlv.one(bpp, 0xBF36).require(0xA1)
            val segments = sequence.children()
            require(segments.isNotEmpty() && segments.all { it.tag == 0x88 && it.value.size > MAC_LENGTH })
            parse(Der.concat(*segments.map { it.value.copyOfRange(0, it.value.size - MAC_LENGTH) }.toTypedArray()))
        } catch (e: IllegalArgumentException) {
            null
        }

        private const val MAC_LENGTH = 8
    }
}

/** NotificationMetadata (5.7.10). [event] is one NotificationEvents bit. */
class NotificationMetadata(val seq: Int, val event: Int, val address: String, val iccid: String?) {
    override fun toString() = "NotificationMetadata(seq=$seq, event=$event)"

    companion object {
        const val TAG = 0xBF2F

        fun parse(element: Tlv): NotificationMetadata {
            require(element.tag == TAG) { "unexpected tag" }
            val event = element.require(0x81).bits().toFlags() and NotificationEvents.ALL
            require(Integer.bitCount(event) == 1) { "bad event" }
            return NotificationMetadata(
                seq = element.require(0x80).int(),
                event = event,
                address = element.require(0x0C).utf8(),
                iccid = element.child(0x5A)?.value?.let { Iccid.decode(it) },
            )
        }
    }
}

/** ProfileInstallationResult (2.5.6): the outcome the eUICC signs and keeps until it is sent. */
class InstallResult(
    val transactionId: ByteArray,
    val metadata: NotificationMetadata,
    val smdpOid: String,
    val success: Boolean,
    /** BppCommandId and ErrorReason of an errorResult. */
    val bppCommandId: Int?,
    val errorReason: Int?,
) {
    override fun toString() = "InstallResult(success=$success, command=$bppCommandId, reason=$errorReason)"

    companion object {
        const val TAG = 0xBF37

        fun parse(element: Tlv): InstallResult {
            require(element.tag == TAG) { "unexpected tag" }
            val data = element.require(0xBF27)
            val result = data.require(0xA2)
            val choice = result.children().singleOrNull() ?: throw IllegalArgumentException("bad result")
            val success = when (choice.tag) {
                0xA0 -> true
                0xA1 -> false
                else -> throw IllegalArgumentException("bad result")
            }
            return InstallResult(
                transactionId = data.require(0x80).value,
                metadata = NotificationMetadata.parse(data.require(NotificationMetadata.TAG)),
                smdpOid = data.require(0x06).oid(),
                success = success,
                bppCommandId = if (success) null else choice.child(0x80)?.int(),
                errorReason = if (success) null else choice.child(0x81)?.int(),
            )
        }
    }
}

/**
 * PendingNotification (5.7.10): a ProfileInstallationResult or an OtherSignedNotification, as
 * the eUICC keeps it. [raw] is what ES9+.HandleNotification sends.
 */
class PendingNotification(val raw: ByteArray, val metadata: NotificationMetadata, val install: InstallResult?) {
    override fun toString() = "PendingNotification($metadata, install=${install != null})"

    companion object {
        fun parse(raw: ByteArray): PendingNotification {
            val element = Tlv.one(raw)
            return when (element.tag) {
                InstallResult.TAG -> InstallResult.parse(element).let { PendingNotification(raw, it.metadata, it) }
                0x30 -> PendingNotification(raw, NotificationMetadata.parse(element.require(NotificationMetadata.TAG)), null)
                else -> throw IllegalArgumentException("unexpected tag")
            }
        }

        fun parseOrNull(raw: ByteArray?): PendingNotification? =
            raw?.let { try { parse(it) } catch (e: IllegalArgumentException) { null } }
    }
}

/** Card responses the framework returns whole; the download checks their shape. */
object CardResponses {
    /** AuthenticateServerResponse (5.7.13) is authenticateResponseOk [0] for [transactionId]. */
    fun authenticateServerOk(data: ByteArray, transactionId: ByteArray): Boolean = check {
        val ok = Tlv.one(data, 0xBF38).children().single()
        ok.tag == 0xA0 && ok.require(0x30).require(0x80).value.contentEquals(transactionId)
    }

    /** PrepareDownloadResponse (5.7.5) is downloadResponseOk [0] for [transactionId]. */
    fun prepareDownloadOk(data: ByteArray, transactionId: ByteArray): Boolean = check {
        val ok = Tlv.one(data, 0xBF21).children().single()
        ok.tag == 0xA0 && ok.require(0x30).require(0x80).value.contentEquals(transactionId)
    }

    /** CancelSessionResponse (5.7.14) is cancelSessionResponseOk [0]. */
    fun cancelSessionOk(data: ByteArray): Boolean = check {
        Tlv.one(data, 0xBF41).children().single().tag == 0xA0
    }

    private inline fun check(block: () -> Boolean): Boolean = try {
        block()
    } catch (e: IllegalArgumentException) {
        false
    } catch (e: NoSuchElementException) {
        false
    }
}

/** CancelSessionReason (5.7.14). Only postponed and timeout keep the operator's download order. */
object CancelReason {
    const val END_USER_REJECTION = 0
    const val POSTPONED = 1
    const val TIMEOUT = 2
    const val PPR_NOT_ALLOWED = 3
}
