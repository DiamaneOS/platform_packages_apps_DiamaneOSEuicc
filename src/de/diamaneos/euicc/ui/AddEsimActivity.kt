// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.ui

import android.os.Bundle
import android.os.UserManager
import android.view.MenuItem
import android.view.WindowManager
import android.widget.Toast
import com.android.settingslib.collapsingtoolbar.CollapsingToolbarBaseActivity
import de.diamaneos.euicc.R

/**
 * "Add eSIM": from the eSIM screen, and from Settings' "Add SIM" through the framework's
 * EuiccManager.ACTION_PROVISION_EMBEDDED_SUBSCRIPTION (the alias in the manifest). For the
 * system user only, and not when changes to mobile networks are restricted. Secure window:
 * activation and confirmation codes stay out of screenshots and the recents preview.
 */
class AddEsimActivity : CollapsingToolbarBaseActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
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
            supportFragmentManager.beginTransaction()
                .replace(
                    com.android.settingslib.collapsingtoolbar.R.id.content_frame,
                    AddEsimFragment(),
                )
                .commit()
        }
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        if (item.itemId == android.R.id.home) {
            finish()
            return true
        }
        return super.onOptionsItemSelected(item)
    }
}
