// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.fuzz

import de.diamaneos.euicc.core.Der
import de.diamaneos.euicc.core.ProfileMetadata

/**
 * The consent metadata against the Bound Profile Package, as DownloadFlow compares them before
 * the package goes to the eUICC (3.1.3.2). Input: two parts, the consent StoreMetadataRequest
 * and the package.
 * - Neither parse throws anything but IllegalArgumentException, fromBoundProfilePackage nothing.
 * - When the flow would install the package, the metadata the eUICC receives (the '88'
 *   segments of the first [1] component, without their MACs) reads, under every reader model,
 *   with the class and rules the user agreed to, no extra notification events, and the same
 *   owner when there are rules.
 */
object BppFuzz {
    private const val MAC = 8

    @JvmStatic
    fun fuzzerTestOneInput(data: ByteArray) {
        val (consentBytes, bpp) = Parts.split(data, 2)
        val packaged = ProfileMetadata.fromBoundProfilePackage(bpp)
        val consent = orIae { ProfileMetadata.parse(consentBytes) } ?: return
        if (packaged == null) return
        if (packaged.policyRules != consent.policyRules || consent.refusedChange(packaged) != null) return
        invariant(parsedTagsCanonical(bpp)) { "package with a tag in a forbidden form accepted" }
        val shown = MetadataModels.shown(consent)
        val sent = framework(bpp) ?: throw Violation("the framework would not find the metadata segments")
        for (model in MetadataModels.MODELS) {
            val v = MetadataModels.read(sent, model) ?: throw Violation("installed metadata unreadable under $model")
            invariant(v.profileClass == shown.profileClass) { "installed class differs under $model" }
            invariant(v.ppr == shown.ppr) { "installed rules differ under $model" }
            invariant(shown.events.containsAll(v.events)) { "installed events exceed the consent under $model" }
            if (consent.policyRules != 0) invariant(v.owner == shown.owner) { "installed owner differs under $model" }
        }
    }

    /**
     * What the eUICC receives as StoreMetadataRequest: the framework (EuiccPort) takes the first
     * [1] child of the package and sends its '88' children, the eUICC joins them without the MACs.
     */
    private fun framework(bpp: ByteArray): ByteArray? = try {
        frameworkOrThrow(bpp)
    } catch (e: RefDer.Bad) {
        null
    }

    private fun frameworkOrThrow(bpp: ByteArray): ByteArray? {
        val top = RefDer.decode(bpp).singleOrNull() ?: return null
        val seq = top.children().firstOrNull { it.packedTag == 0xA1 } ?: return null
        val segments = seq.children().filter { it.packedTag == 0x88 }
        if (segments.any { it.content.size < MAC }) return null
        return Der.concat(*segments.map { it.content.copyOfRange(0, it.content.size - MAC) }.toTypedArray())
    }

    /**
     * The tags this app and the framework read are in allowed forms: the package, its components
     * and the '88' segments. The profile elements ('A3') are not read for the consent check.
     */
    private fun parsedTagsCanonical(bpp: ByteArray): Boolean = try {
        val top = RefDer.decode(bpp)
        val components = top.flatMap { it.children() }
        val segments = components.firstOrNull { it.packedTag == 0xA1 }?.children().orEmpty()
        (top + components + segments).none { it.badTag }
    } catch (e: RefDer.Bad) {
        true
    }

    /** A package around [metadata], split into [segments] '88' segments with dummy MACs. */
    fun packageOf(metadata: ByteArray, segments: Int): ByteArray {
        val mac = ByteArray(MAC) { 0x77 }
        val cuts = (0..segments).map { metadata.size * it / segments }
        val parts = (0 until segments).map { Der.tlv(0x88, metadata.copyOfRange(cuts[it], cuts[it + 1]) + mac) }
        return Der.tlv(0xBF36,
            Der.tlv(0xBF23, Der.tlv(0x80, ByteArray(16))),
            Der.tlv(0xA0, Der.tlv(0x87, ByteArray(20))),
            Der.tlv(0xA1, *parts.toTypedArray()),
            Der.tlv(0xA3, Der.tlv(0x86, ByteArray(40))))
    }
}
