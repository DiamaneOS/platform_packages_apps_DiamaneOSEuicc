// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.ui

import android.content.Intent
import android.os.Bundle
import android.os.UserManager
import android.view.MenuItem
import android.widget.Toast
import com.android.settingslib.collapsingtoolbar.CollapsingToolbarBaseActivity
import de.diamaneos.euicc.R

/**
 * "Add eSIM": from the eSIM screen, and from Settings' "Add SIM" through the framework's
 * EuiccManager.ACTION_PROVISION_EMBEDDED_SUBSCRIPTION (the alias in the manifest), and with a
 * scanned code from [OpenCodeActivity]. For the system user only, and not when changes to
 * mobile networks are restricted. Secure window: activation and confirmation codes stay out of
 * screenshots and the recents preview, and other apps' overlays are hidden.
 */
class AddEsimActivity : CollapsingToolbarBaseActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        AddEsimFragment.secure(window)
        val users = getSystemService(UserManager::class.java)
        if (!users.isSystemUser) {
            finish()
            return
        }
        if (users.hasUserRestriction(UserManager.DISALLOW_CONFIG_MOBILE_NETWORKS)) {
            Toast.makeText(this, R.string.add_restricted, Toast.LENGTH_LONG).show()
            finish()
            return
        }
        title = getString(R.string.add_title)
        if (savedInstanceState == null) {
            val fragment = AddEsimFragment()
            takeCode(intent)?.let(fragment::offer)
            supportFragmentManager.beginTransaction()
                .replace(com.android.settingslib.collapsingtoolbar.R.id.content_frame, fragment)
                .commit()
        }
    }

    /** [OpenCodeActivity] brings back the screen that started the scan, with the code. */
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        val code = takeCode(intent) ?: return
        val fragment = supportFragmentManager
            .findFragmentById(com.android.settingslib.collapsingtoolbar.R.id.content_frame)
        (fragment as? AddEsimFragment)?.offer(code)
    }

    /** Taken once: not offered again when the activity is recreated. */
    private fun takeCode(intent: Intent): String? =
        intent.getStringExtra(EXTRA_CODE)?.also { intent.removeExtra(EXTRA_CODE) }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        if (item.itemId == android.R.id.home) {
            finish()
            return true
        }
        return super.onOptionsItemSelected(item)
    }

    companion object {
        /** A scanned activation code, from [OpenCodeActivity] only (this activity is not exported). */
        const val EXTRA_CODE = "de.diamaneos.euicc.extra.CODE"
    }
}
