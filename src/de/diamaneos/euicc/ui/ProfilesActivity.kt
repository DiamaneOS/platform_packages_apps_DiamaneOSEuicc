// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.ui

import android.os.Bundle
import android.os.UserManager
import android.view.MenuItem
import com.android.settingslib.collapsingtoolbar.CollapsingToolbarBaseActivity

/** The eSIM screen, in the Settings style. Only for the system user, who owns the SIMs. */
class ProfilesActivity : CollapsingToolbarBaseActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!getSystemService(UserManager::class.java).isSystemUser) {
            finish()
            return
        }
        if (savedInstanceState == null) {
            supportFragmentManager.beginTransaction()
                .replace(
                    com.android.settingslib.collapsingtoolbar.R.id.content_frame,
                    ProfilesFragment(),
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
