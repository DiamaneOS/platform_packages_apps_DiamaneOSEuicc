// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.ui

import android.app.Activity
import android.content.Intent
import android.os.Bundle

/**
 * "Open with" for a scanned activation code: the camera app's QR result offers the apps that
 * open its text as a link, so an "LPA:" code goes straight to Add eSIM, without the clipboard.
 * - Exported, so any app on the phone can hand over a code. It only fills in the code: the user
 *   still agrees on the dialog that names the server before anything connects, and the Add eSIM
 *   windows hide other apps' overlays. Not browsable, so web pages can't open it.
 * - Brings back the Add eSIM screen that started the scan when it is below the camera in this
 *   task (closing the camera), or else opens a new one. Add eSIM parses and checks the code.
 */
class OpenCodeActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val code = intent.takeIf { it.action == Intent.ACTION_VIEW }?.dataString
        if (code != null && code.length <= MAX_INPUT) {
            startActivity(
                Intent(this, AddEsimActivity::class.java)
                    .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
                    .putExtra(AddEsimActivity.EXTRA_CODE, code),
            )
        }
        finish()
    }

    private companion object {
        /** Far above any valid code (ActivationCode.MAX_LENGTH); Add eSIM rejects the rest. */
        const val MAX_INPUT = 1024
    }
}
