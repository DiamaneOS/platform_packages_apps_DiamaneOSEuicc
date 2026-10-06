// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.core

/** SGP.22 VersionType: three octets, major.minor.revision. */
data class Version(val major: Int, val minor: Int, val revision: Int) : Comparable<Version> {
    override fun compareTo(other: Version): Int =
        compareValuesBy(this, other, Version::major, Version::minor, Version::revision)

    override fun toString() = "$major.$minor.$revision"

    companion object {
        fun parse(bytes: ByteArray): Version {
            require(bytes.size == 3) { "bad version" }
            return Version(bytes[0].toInt() and 0xFF, bytes[1].toInt() and 0xFF, bytes[2].toInt() and 0xFF)
        }
    }
}

/**
 * SGP.22 EUICCInfo1 (section 5.7.8): the SGP.22 version and the CI public key identifiers the
 * eUICC can verify with and sign for. Sent as is in ES9+.InitiateAuthentication.
 */
class EuiccInfo1(
    val svn: Version,
    val ciForVerification: List<ByteArray>,
    val ciForSigning: List<ByteArray>,
) {
    companion object {
        const val TAG = 0xBF20

        fun parse(data: ByteArray): EuiccInfo1 {
            val info = Tlv.one(data, TAG)
            return EuiccInfo1(
                svn = Version.parse(info.require(0x82).value),
                ciForVerification = keyIds(info.require(0xA9)),
                ciForSigning = keyIds(info.require(0xAA)),
            )
        }

        /** SEQUENCE OF SubjectKeyIdentifier (OCTET STRING). */
        internal fun keyIds(list: Tlv): List<ByteArray> =
            list.children().map {
                require(it.tag == 0x04 && it.value.size in 1..32) { "bad key identifier" }
                it.value
            }
    }
}

/** SGP.22 EUICCInfo2 (section 5.7.8), as EuiccCardManager.requestEuiccInfo2 returns it. */
object EuiccInfo2 {
    const val TAG_EUICC_INFO2 = 0xBF22

    /** euiccFirmwareVer [3] VersionType: three bytes, major.minor.revision. */
    const val TAG_FIRMWARE_VERSION = 0x83

    /** RspCapability bit names (SGP.22 5.7.8). */
    val RSP_CAPABILITIES = listOf(
        "additionalProfile", "crlSupport", "rpmSupport", "testProfileSupport",
        "deviceInfoExtensibilitySupport", "serviceSpecificDataSupport",
    )

    /** What the dump shows: versions, capabilities and CI identifiers, no identifiers of the card. */
    class Summary(
        val profileVersion: Version?,
        val svn: Version?,
        val firmware: Version?,
        val rspCapabilities: List<String>,
        val ciForVerification: List<ByteArray>,
        val ciForSigning: List<ByteArray>,
        val category: Int?,
        val ppVersion: Version?,
    )

    /** The eUICC firmware version as "major.minor.revision", or null if absent or malformed. */
    fun firmwareVersion(data: ByteArray?): String? = summary(data)?.firmware?.toString()

    /** Null if [data] is absent or not an EUICCInfo2. Optional fields that do not parse are null. */
    fun summary(data: ByteArray?): Summary? {
        if (data == null) return null
        return try {
            val info = Tlv.parse(data).firstOrNull { it.tag == TAG_EUICC_INFO2 } ?: return null
            val children = Tlv.parse(info.value)
            fun version(tag: Int) = children.firstOrNull { it.tag == tag }
                ?.let { if (it.value.size == 3) Version.parse(it.value) else null }
            fun keyIds(tag: Int) = children.firstOrNull { it.tag == tag }
                ?.let { runCatching { EuiccInfo1.keyIds(it) }.getOrNull() }.orEmpty()
            val capability = children.firstOrNull { it.tag == 0x88 }?.let { runCatching { it.bits() }.getOrNull() }
            Summary(
                profileVersion = version(0x81),
                svn = version(0x82),
                firmware = version(TAG_FIRMWARE_VERSION),
                rspCapabilities = RSP_CAPABILITIES.filterIndexed { bit, _ -> capability?.get(bit) == true },
                ciForVerification = keyIds(0xA9),
                ciForSigning = keyIds(0xAA),
                category = children.firstOrNull { it.tag == 0x8B }?.let { runCatching { it.int() }.getOrNull() },
                // ppVersion is the first universal OCTET STRING (untagged) of the sequence.
                ppVersion = children.firstOrNull { it.tag == 0x04 && it.value.size == 3 }?.let { Version.parse(it.value) },
            )
        } catch (e: IllegalArgumentException) {
            null
        }
    }
}
