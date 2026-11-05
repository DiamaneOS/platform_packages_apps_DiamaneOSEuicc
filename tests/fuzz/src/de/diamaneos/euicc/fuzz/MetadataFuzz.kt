// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.fuzz

import de.diamaneos.euicc.core.Der
import de.diamaneos.euicc.core.ProfileMetadata

/**
 * ProfileMetadata.parse: the StoreMetadataRequest of ES9+.AuthenticateClient, which the consent
 * dialog shows.
 * - Only IllegalArgumentException may come out.
 * - The class is one the dialog can name (test, provisioning, operational).
 * - Every reader model (MetadataModels) reads the same class, rules, events, owner and labels.
 * - The same bytes inside a Bound Profile Package read the same, and match themselves.
 * - The name and provider as shown have no character that hides or reorders text (ConsentChecks).
 */
object MetadataFuzz {
    @JvmStatic
    fun fuzzerTestOneInput(data: ByteArray) {
        val m = orIae { ProfileMetadata.parse(data) } ?: return
        check(data, m)
    }

    fun check(data: ByteArray, m: ProfileMetadata) {
        invariant(m.profileClass in 0..2) { "class ${m.profileClass} accepted" }
        invariant(m.profileName.length <= 64 && m.serviceProviderName.length <= 32) { "label length" }
        MetadataModels.disagreement(data, MetadataModels.shown(m))?.let { throw Violation("ambiguous metadata: $it") }
        invariant(m.refusedChange(m) == null && m.labelChanges(m).isEmpty()) { "differs from itself" }
        if (data.size <= 0xFFFF) {
            val inPackage = ProfileMetadata.fromBoundProfilePackage(BppFuzz.packageOf(data, 3))
            invariant(inPackage != null && m.refusedChange(inPackage) == null && m.labelChanges(inPackage).isEmpty()) { "package reading differs" }
        }
        ConsentChecks.check(m)
        // Re-encoding the element as DER reads back the same.
        val again = ProfileMetadata.parse(Der.tlv(ProfileMetadata.TAG, *orIae { de.diamaneos.euicc.core.Tlv.one(data).children() }!!.map { it.encoded() }.toTypedArray()))
        invariant(m.refusedChange(again) == null && again.refusedChange(m) == null && m.labelChanges(again).isEmpty()) { "DER re-encoding differs" }
    }
}
