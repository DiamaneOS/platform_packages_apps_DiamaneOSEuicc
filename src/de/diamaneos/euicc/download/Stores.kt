// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.download

import android.content.Context
import android.os.UserManager
import android.util.Log
import de.diamaneos.euicc.R
import de.diamaneos.euicc.core.GsmaCi
import de.diamaneos.euicc.core.OwnedSet
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64

/**
 * The GSMA CI root certificates shipped in res/raw (sources in README.md): the only TLS trust
 * anchors of every ES9+ and ES11 connection. A root that is not a known production CI,
 * self-signed and valid is skipped.
 */
object CiRoots {
    private val RESOURCES = intArrayOf(R.raw.gsma_ci_rsp2_root_ci1, R.raw.gsma_ci_oiste_g1)

    @Volatile
    private var cached: Map<String, X509Certificate>? = null

    fun get(context: Context): Map<String, X509Certificate> {
        cached?.let { return it }
        val factory = CertificateFactory.getInstance("X.509")
        val roots = LinkedHashMap<String, X509Certificate>()
        for (id in RESOURCES) {
            try {
                val cert = context.resources.openRawResource(id).use {
                    factory.generateCertificate(it) as X509Certificate
                }
                GsmaCi.checkRoot(cert)?.let { roots[it] = cert }
            } catch (e: CertificateException) {
                Log.w(TAG, "CI root unreadable")
            }
        }
        Log.i(TAG, "CI roots: ${roots.size} of ${RESOURCES.size}")
        return roots.also { cached = it }
    }
}

/**
 * Which profiles this app installed: salted hashes of their ICCIDs (OwnedSet) in
 * credential-encrypted app storage, so only after the first unlock. Used only to decide which
 * notifications this app may send.
 */
object OwnedProfiles {
    private const val PREFS = "owned_profiles"
    private const val KEY_SALT = "salt"
    private const val KEY_HASHES = "hashes"

    @Synchronized
    fun load(context: Context): OwnedSet? {
        if (!unlocked(context)) return null
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        var salt = prefs.getString(KEY_SALT, null)?.let { runCatching { Base64.getDecoder().decode(it) }.getOrNull() }
        if (salt == null || salt.size < 16) {
            salt = ByteArray(32).also { SecureRandom().nextBytes(it) }
            prefs.edit().putString(KEY_SALT, Base64.getEncoder().encodeToString(salt))
                .remove(KEY_HASHES).commit()
        }
        return OwnedSet(salt, prefs.getStringSet(KEY_HASHES, null)?.toList().orEmpty())
    }

    @Synchronized
    fun add(context: Context, iccid: String) = change(context) { it.add(iccid) }

    @Synchronized
    fun remove(context: Context, iccid: String) = change(context) { it.remove(iccid) }

    @Synchronized
    fun contains(context: Context, iccid: String): Boolean = load(context)?.contains(iccid) == true

    private fun change(context: Context, edit: (OwnedSet) -> Unit) {
        val set = load(context) ?: return
        edit(set)
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putStringSet(KEY_HASHES, set.snapshot()).commit()
    }

    private fun unlocked(context: Context) =
        context.getSystemService(UserManager::class.java)?.isUserUnlocked == true
}

private const val TAG = "DiamaneOSEuicc"
