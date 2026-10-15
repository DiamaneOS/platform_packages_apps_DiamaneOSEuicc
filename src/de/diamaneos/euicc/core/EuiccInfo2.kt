// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.core

/** A BER-TLV element: tag (all tag bytes, big-endian) and value. */
class Tlv(val tag: Int, val value: ByteArray) {
    companion object {
        /**
         * The elements in [data] at one level. Throws IllegalArgumentException on malformed
         * input: truncated tag, length or value, indefinite or over-long lengths, tags over
         * three bytes.
         */
        fun parse(data: ByteArray): List<Tlv> {
            val result = ArrayList<Tlv>()
            var pos = 0
            while (pos < data.size) {
                var tag = byteAt(data, pos++)
                if (tag and 0x1F == 0x1F) {
                    var count = 0
                    do {
                        val next = byteAt(data, pos++)
                        tag = (tag shl 8) or next
                        require(++count <= 2) { "tag too long" }
                    } while (next and 0x80 != 0)
                }
                var length = byteAt(data, pos++)
                if (length and 0x80 != 0) {
                    val count = length and 0x7F
                    require(count in 1..3) { "unsupported length" }
                    length = 0
                    repeat(count) { length = (length shl 8) or byteAt(data, pos++) }
                }
                require(length <= data.size - pos) { "truncated value" }
                result += Tlv(tag, data.copyOfRange(pos, pos + length))
                pos += length
            }
            return result
        }

        private fun byteAt(data: ByteArray, pos: Int): Int {
            require(pos < data.size) { "truncated" }
            return data[pos].toInt() and 0xFF
        }
    }
}

/** SGP.22 EUICCInfo2, as EuiccCardManager.requestEuiccInfo2 returns it. */
object EuiccInfo2 {
    const val TAG_EUICC_INFO2 = 0xBF22

    /** euiccFirmwareVer [3] VersionType: three bytes, major.minor.revision. */
    const val TAG_FIRMWARE_VERSION = 0x83

    /** The eUICC firmware version as "major.minor.revision", or null if absent or malformed. */
    fun firmwareVersion(data: ByteArray?): String? {
        if (data == null) return null
        return try {
            val info = Tlv.parse(data).firstOrNull { it.tag == TAG_EUICC_INFO2 } ?: return null
            val version = Tlv.parse(info.value).firstOrNull { it.tag == TAG_FIRMWARE_VERSION }
                ?: return null
            if (version.value.size != 3) return null
            version.value.joinToString(".") { (it.toInt() and 0xFF).toString() }
        } catch (e: IllegalArgumentException) {
            null
        }
    }
}
