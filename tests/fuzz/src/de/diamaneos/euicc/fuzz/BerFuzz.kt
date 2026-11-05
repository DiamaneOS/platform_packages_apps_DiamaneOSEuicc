// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.fuzz

import de.diamaneos.euicc.core.Der
import de.diamaneos.euicc.core.Hex
import de.diamaneos.euicc.core.Iccid
import de.diamaneos.euicc.core.Tlv

/**
 * Tlv.parse and the primitive readers (Ber.kt), on any bytes.
 * - Only IllegalArgumentException may come out.
 * - Accepted elements re-encode (Der.tlv) to bytes that parse to the same tree, and to the
 *   input itself when its lengths are minimal: only the length form may be normalised.
 * - No tag in a form X.690 8.1.2 forbids is accepted (it would name another component for
 *   a reader that decodes tag numbers).
 * - INTEGER, OID and BIT STRING readers agree with the reference reading.
 */
object BerFuzz {
    @JvmStatic
    fun fuzzerTestOneInput(data: ByteArray) {
        val elements = orIae { Tlv.parse(data) } ?: return
        val ref = RefDer.decode(data)
        invariant(ref.none { it.badTag }) { "tag in a forbidden form accepted" }
        invariant(ref.size == elements.size) { "element count differs from reference" }
        val reencoded = Der.concat(*elements.map { it.encoded() }.toTypedArray())
        if (ref.none { it.longLength }) invariant(reencoded.contentEquals(data)) { "re-encoding differs" }
        walk(elements, ref, 0)
    }

    private fun walk(elements: List<Tlv>, ref: List<RefDer.Node>, depth: Int) {
        for ((e, r) in elements.zip(ref)) {
            invariant(e.tag == r.packedTag && e.value.contentEquals(r.content)) { "element differs from reference" }
            val again = Tlv.one(e.encoded())
            invariant(again.tag == e.tag && again.value.contentEquals(e.value)) { "round trip differs" }
            primitives(e)
            if (depth < 32 && e.constructed) {
                val children = orIae { e.children() } ?: continue
                val refChildren = RefDer.decode(e.value)
                invariant(refChildren.none { it.badTag }) { "nested tag in a forbidden form accepted" }
                walk(children, refChildren, depth + 1)
            }
        }
    }

    private fun primitives(e: Tlv) {
        orIae { e.int() }?.let { v ->
            invariant(e.value.size in 1..4) { "INTEGER size" }
            if (RefDer.intMinimal(e.value)) invariant(Der.int(v, e.tag).contentEquals(e.encoded())) { "INTEGER round trip" }
        }
        orIae { e.bool() }?.let { invariant(e.value.size == 1 && it == (e.value[0].toInt() != 0)) { "BOOLEAN" } }
        orIae { e.bits() }?.let { b ->
            val ref = RefDer.bits(e.value)
            if (ref != null) {
                for (bit in 0 until minOf(b.size, 64)) invariant(b[bit] == (bit in ref)) { "BIT STRING bit $bit" }
                invariant(b.toFlags() == ref.filter { it < 31 }.fold(0) { acc, n -> acc or (1 shl n) }) { "toFlags" }
            }
        }
        orIae { e.oid() }?.let { dotted ->
            invariant(Der.oid(dotted, e.tag).contentEquals(e.encoded())) { "OID round trip" }
        }
        orIae { e.utf8() }?.let { s ->
            invariant(s.toByteArray(Charsets.UTF_8).contentEquals(e.value)) { "UTF-8 round trip" }
        }
        Iccid.decode(e.value)?.let { digits ->
            invariant(digits.length in 18..22 && digits.all { it in '0'..'9' }) { "ICCID digits" }
        }
        Hex.decode(Hex.encode(e.value))?.let { invariant(it.contentEquals(e.value)) { "hex round trip" } }
    }
}
