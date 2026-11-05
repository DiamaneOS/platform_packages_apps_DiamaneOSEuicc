// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.fuzz

import de.diamaneos.euicc.core.ProfileMetadata

/**
 * How another reader (the eUICC, a later Android) could read a StoreMetadataRequest that this
 * app accepted. Each model makes one choice X.690 BER leaves open to a lenient decoder: which of
 * two equal tags wins, whether a tag in a forbidden form names the same component, whether the
 * unused bits of a BIT STRING count, which byte of a long ProfileClass is the value. An accepted
 * input must read the same under every model on the fields the consent check compares.
 */
object MetadataModels {
    class View(
        val profileClass: Int?,
        val ppr: Set<Int>,
        val events: Set<Int>,
        val owner: List<String>?,
        val name: String?,
        val provider: String?,
    ) {
        override fun toString() = "class=$profileClass ppr=$ppr events=$events owner=${owner != null}"
    }

    enum class Duplicates { FIRST, LAST }
    enum class Bits { RESPECT_UNUSED, IGNORE_UNUSED }
    enum class ClassByte { INTEGER, FIRST_BYTE, LAST_BYTE }

    class Model(val dup: Duplicates, val bits: Bits, val classByte: ClassByte) {
        override fun toString() = "$dup/$bits/$classByte"
    }

    val MODELS = Duplicates.entries.flatMap { d ->
        Bits.entries.flatMap { b -> ClassByte.entries.map { c -> Model(d, b, c) } }
    }

    private const val CONTEXT = 2

    /** The view of [data] (a whole BF25 element) under [model]. Null if the model cannot read it. */
    fun read(data: ByteArray, model: Model): View? = try {
        readOrThrow(data, model)
    } catch (e: RefDer.Bad) {
        null
    }

    private fun readOrThrow(data: ByteArray, model: Model): View? {
        val top = RefDer.decode(data).singleOrNull() ?: return null
        if (top.tagClass != CONTEXT || !top.constructed || top.number != 37L) return null
        val children = top.children()
        fun pick(list: List<RefDer.Node>, cls: Int, constructed: Boolean, number: Long): RefDer.Node? {
            val all = list.filter { it.tagClass == cls && it.constructed == constructed && it.number == number }
            return if (model.dup == Duplicates.FIRST) all.firstOrNull() else all.lastOrNull()
        }
        fun bitSet(v: ByteArray): Set<Int> = when (model.bits) {
            Bits.RESPECT_UNUSED -> RefDer.bits(v) ?: lenientBits(v)
            Bits.IGNORE_UNUSED -> RefDer.bitsIgnoringUnused(v)
        }
        val classNode = pick(children, CONTEXT, false, 21)
        val profileClass = classNode?.content?.let { v ->
            if (v.isEmpty()) return null
            when (model.classByte) {
                ClassByte.INTEGER -> if (v.size > 4) return null else v.fold(v[0].toInt() shr 8) { acc, b -> (acc shl 8) or (b.toInt() and 0xFF) }
                ClassByte.FIRST_BYTE -> v.first().toInt()
                ClassByte.LAST_BYTE -> v.last().toInt()
            }
        } ?: ProfileMetadata.CLASS_OPERATIONAL
        val ppr = pick(children, CONTEXT, false, 25)?.content?.let { bitSet(it) }.orEmpty()
        val events = HashSet<Int>()
        pick(children, CONTEXT, true, 22)?.children()?.forEach { entry ->
            val e = pick(entry.children(), CONTEXT, false, 0) ?: return null
            events += bitSet(e.content)
        }
        val owner = pick(children, CONTEXT, true, 23)?.let { o ->
            val c = o.children()
            listOf(
                pick(c, CONTEXT, false, 0)?.content?.hex() ?: return null,
                pick(c, CONTEXT, false, 1)?.content?.hex() ?: "-",
                pick(c, CONTEXT, false, 2)?.content?.hex() ?: "-",
            )
        }
        return View(
            profileClass = profileClass,
            ppr = ppr.filter { it < 31 }.toSet(),
            events = events.filter { it < 4 }.toSet(),
            owner = owner,
            // A missing name or provider reads as empty, as the app shows it.
            name = pick(children, CONTEXT, false, 18)?.content?.let { String(it, Charsets.UTF_8) }.orEmpty(),
            provider = pick(children, CONTEXT, false, 17)?.content?.let { String(it, Charsets.UTF_8) }.orEmpty(),
        )
    }

    /** What this app's parse shows and compares, in the same terms. */
    fun shown(m: ProfileMetadata) = View(
        profileClass = m.profileClass,
        ppr = (0 until 31).filter { m.ppr and (1 shl it) != 0 }.toSet(),
        events = (0 until 4).filter { m.notifiedEvents and (1 shl it) != 0 }.toSet(),
        owner = m.owner?.let { listOf(it.mccMnc.hex(), it.gid1?.hex() ?: "-", it.gid2?.hex() ?: "-") },
        name = m.profileName,
        provider = m.serviceProviderName,
    )

    /**
     * The first model under which [data] reads differently from [shown] on a compared field, or
     * null. [labels]: names count too (the consent shows them).
     */
    fun disagreement(data: ByteArray, shown: View, labels: Boolean = true): String? {
        for (model in MODELS) {
            val v = read(data, model) ?: return "unreadable under $model"
            val diff = when {
                v.profileClass != shown.profileClass -> "class"
                v.ppr != shown.ppr -> "ppr"
                v.events != shown.events -> "events"
                v.owner != shown.owner -> "owner"
                labels && v.name != shown.name -> "name"
                labels && v.provider != shown.provider -> "provider"
                else -> null
            }
            if (diff != null) return "$diff differs under $model ($shown vs $v)"
        }
        return null
    }

    private fun lenientBits(v: ByteArray): Set<Int> {
        if (v.isEmpty()) return emptySet()
        val unused = (v[0].toInt() and 0xFF).coerceAtMost(7)
        val size = (v.size - 1) * 8 - unused
        return RefDer.bitsIgnoringUnused(v).filter { it < size }.toSet()
    }

    fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }
}
