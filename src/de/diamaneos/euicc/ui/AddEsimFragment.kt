// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.ui

import android.app.AlertDialog
import android.content.ActivityNotFoundException
import android.content.ClipboardManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.res.Resources
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.MediaStore
import android.text.Editable
import android.text.InputType
import android.text.TextWatcher
import android.view.View
import android.view.Window
import android.view.WindowManager
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.preference.Preference
import androidx.preference.PreferenceCategory
import com.android.settingslib.widget.SettingsBasePreferenceFragment
import de.diamaneos.euicc.R
import de.diamaneos.euicc.card.CardClient
import de.diamaneos.euicc.card.Euicc
import de.diamaneos.euicc.core.ActivationCode
import de.diamaneos.euicc.core.ConfirmRequest
import de.diamaneos.euicc.core.Confirmation
import de.diamaneos.euicc.core.ConfirmationCode
import de.diamaneos.euicc.core.Failure
import de.diamaneos.euicc.core.Fqdn
import de.diamaneos.euicc.core.NotificationEvents
import de.diamaneos.euicc.core.Outcome
import de.diamaneos.euicc.core.ProfileMetadata
import de.diamaneos.euicc.core.RspException
import de.diamaneos.euicc.core.Step
import de.diamaneos.euicc.download.RspTask
import de.diamaneos.euicc.download.RspTasks
import java.util.concurrent.Executors

/**
 * Add an eSIM: scan (the camera app's QR scanner, then "Open with" or paste), paste or type an
 * activation code, or search the eUICC's discovery server; or check a code without using it.
 * - Nothing contacts a server before the user agrees on a dialog that names the server and
 *   what it receives.
 * - The profile's details are confirmed (with the confirmation code if one is required)
 *   before anything is downloaded; "Not now" and Stop keep the code usable.
 * - No camera permission: QR codes are read by the camera app, then opened with Add eSIM or
 *   pasted (README, "QR codes").
 */
class AddEsimFragment : SettingsBasePreferenceFragment(), RspTask.Listener {
    private val worker = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private lateinit var appContext: Context
    private lateinit var client: CardClient
    private lateinit var status: Preference
    private lateinit var stop: Preference
    private lateinit var add: PreferenceCategory
    private lateinit var more: PreferenceCategory
    private var task: RspTask? = null
    private var confirmDialog: AlertDialog? = null
    private var shownConfirm: ConfirmRequest? = null
    private var shownOutcome: Outcome? = null
    private var awaitingScan = false
    private var offered: String? = null
    private var usedCode: String? = null

    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        val context = preferenceManager.context
        appContext = context.applicationContext
        client = CardClient(appContext)
        awaitingScan = savedInstanceState?.getBoolean(STATE_SCAN) ?: false
        preferenceScreen = preferenceManager.createPreferenceScreen(context)
        status = Preference(context).apply {
            isSelectable = false
            isVisible = false
        }
        stop = action(R.string.stop, 0) { task?.cancel() }.apply { isVisible = false }
        add = PreferenceCategory(context).apply { title = getString(R.string.add_with_code) }
        more = PreferenceCategory(context).apply { title = getString(R.string.add_more) }
        preferenceScreen.addPreference(status)
        preferenceScreen.addPreference(stop)
        preferenceScreen.addPreference(add)
        preferenceScreen.addPreference(more)
        add.addPreference(action(R.string.scan_title, R.string.scan_summary) { scan() })
        add.addPreference(action(R.string.paste_title, R.string.paste_summary) { paste(auto = false) })
        add.addPreference(action(R.string.manual_title, R.string.manual_summary) { manual() })
        more.addPreference(action(R.string.search_title, R.string.search_summary) { search() })
        more.addPreference(action(R.string.check_title, R.string.check_summary) { check() })
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putBoolean(STATE_SCAN, awaitingScan)
    }

    override fun onResume() {
        super.onResume()
        attach(RspTasks.current)
        if (offered != null) {
            awaitingScan = false
            takeOffered()
        } else if (awaitingScan && task == null) {
            awaitingScan = false
            paste(auto = true)
        }
    }

    override fun onPause() {
        task?.listener = null
        confirmDialog?.dismiss()
        confirmDialog = null
        shownConfirm = null
        super.onPause()
    }

    override fun onDestroy() {
        worker.shutdown()
        super.onDestroy()
    }

    override fun onTaskChanged(task: RspTask) {
        if (isAdded && task === this.task) render(task)
    }

    // Getting the code.

    /**
     * A code from the QR result's "Open with" ([OpenCodeActivity]), through the activity:
     * asked about once this screen is in front.
     */
    fun offer(code: String) {
        offered = code
        awaitingScan = false
        if (isResumed) takeOffered()
    }

    private fun takeOffered() {
        val code = offered ?: return
        offered = null
        download(code)
    }

    /**
     * The phone's QR scanner, which SystemUI's QR tile also opens (the camera app's QR mode),
     * or else the camera. The scanned code's "Open with" brings it back here; a copied code is
     * pasted on return.
     */
    private fun scan() {
        for (intent in listOfNotNull(qrScanner(), Intent(MediaStore.INTENT_ACTION_STILL_IMAGE_CAMERA))) {
            try {
                startActivity(intent)
                awaitingScan = true
                Toast.makeText(requireContext(), R.string.scan_hint, Toast.LENGTH_LONG).show()
                return
            } catch (e: ActivityNotFoundException) {
                // Try the next.
            } catch (e: SecurityException) {
                // Not exported: try the next.
            }
        }
        Toast.makeText(requireContext(), R.string.scan_no_camera, Toast.LENGTH_LONG).show()
    }

    /** The OS's QR code scanner activity (config_defaultQrCodeComponent), if it names one. */
    private fun qrScanner(): Intent? {
        val system = Resources.getSystem()
        val id = system.getIdentifier("config_defaultQrCodeComponent", "string", "android")
        if (id == 0) return null
        val component = ComponentName.unflattenFromString(system.getString(id)) ?: return null
        return Intent().setComponent(component)
    }

    /** [auto]: after the camera, quietly, and only for text that looks like a QR activation code. */
    private fun paste(auto: Boolean) {
        val text = clipboardText()
        if (text.isNullOrBlank() || (auto && !text.trim().startsWith("LPA:", ignoreCase = true))) {
            if (!auto) Toast.makeText(requireContext(), R.string.paste_empty, Toast.LENGTH_LONG).show()
            return
        }
        download(text)
    }

    private fun download(text: String) {
        try {
            consent(ActivationCode.parse(text), RspTask.Kind.DOWNLOAD)
        } catch (e: ActivationCode.Invalid) {
            invalid(e)
        }
    }

    /** The SM-DP+ address and activation code as carriers print them; a whole code also works. */
    private fun manual() {
        val context = requireContext()
        val address = field(context, R.string.manual_address, InputType.TYPE_TEXT_VARIATION_URI)
        val token = field(context, R.string.manual_token, InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD)
        AlertDialog.Builder(context)
            .setTitle(R.string.manual_title)
            .setView(column(context, address, token))
            .setPositiveButton(R.string.next) { _, _ ->
                try {
                    val first = address.text.toString()
                    val code = if ('$' in first) ActivationCode.parse(first)
                    else ActivationCode.fromParts(first, token.text.toString())
                    consent(code, RspTask.Kind.DOWNLOAD)
                } catch (e: ActivationCode.Invalid) {
                    invalid(e)
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .showSecure()
    }

    /** A dry run needs only the server: a whole code or just the SM-DP+ address. */
    private fun check() {
        val context = requireContext()
        val input = field(context, R.string.check_input, InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD)
        clipboardText()?.trim()?.takeIf { it.contains('$') }?.let { input.setText(it) }
        AlertDialog.Builder(context)
            .setTitle(R.string.check_title)
            .setMessage(R.string.check_text)
            .setView(column(context, input))
            .setPositiveButton(R.string.next) { _, _ ->
                val text = input.text.toString().trim()
                try {
                    val code = if ('$' in text) ActivationCode.parse(text)
                    else ActivationCode(Fqdn.normalise(text) ?: throw ActivationCode.Invalid(ActivationCode.Problem.ADDRESS), "", null, false)
                    consent(code, RspTask.Kind.CHECK)
                } catch (e: ActivationCode.Invalid) {
                    invalid(e)
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .showSecure()
    }

    /** The eUICC's root SM-DS (ES10a GetEuiccConfiguredAddresses), only when the user asks. */
    private fun search() {
        worker.execute {
            val euicc = client.defaultEuicc()
            val host = euicc?.let { client.smdsAddress(it).value }?.let { Fqdn.normalise(it) }
            main.post {
                if (!isAdded) return@post
                when {
                    euicc == null -> Toast.makeText(requireContext(), R.string.no_euicc, Toast.LENGTH_LONG).show()
                    host == null -> Toast.makeText(requireContext(), R.string.search_no_server, Toast.LENGTH_LONG).show()
                    else -> confirmContact(host, getString(R.string.consent_search, host)) {
                        start { RspTasks.startSearch(appContext, it, host) }
                    }
                }
            }
        }
    }

    // Consent and start.

    private fun consent(code: ActivationCode, kind: RspTask.Kind) {
        val host = code.smdpAddress
        val text = if (kind == RspTask.Kind.CHECK) getString(R.string.consent_check, host)
        else getString(R.string.consent_download, host)
        confirmContact(host, text) {
            // Remember a copied code only if it is this one, to clear it once it is used up.
            usedCode = clipboardText()?.trim()?.takeIf {
                try {
                    ActivationCode.parse(it).encoded() == code.encoded()
                } catch (e: ActivationCode.Invalid) {
                    false
                }
            }
            start {
                if (kind == RspTask.Kind.CHECK) RspTasks.startCheck(appContext, it, code)
                else RspTasks.startDownload(appContext, it, code)
            }
        }
    }

    private fun confirmContact(host: String, text: String, go: () -> Unit) {
        AlertDialog.Builder(requireContext())
            .setTitle(getString(R.string.consent_title, host))
            .setMessage(text)
            .setPositiveButton(R.string.consent_continue) { _, _ -> go() }
            .setNegativeButton(android.R.string.cancel, null)
            .showSecure()
    }

    private fun start(begin: (Euicc) -> RspTask?) {
        worker.execute {
            val euicc = client.defaultEuicc()
            main.post {
                if (!isAdded) return@post
                if (euicc == null) {
                    Toast.makeText(requireContext(), R.string.no_euicc, Toast.LENGTH_LONG).show()
                    return@post
                }
                val started = begin(euicc)
                if (started == null) Toast.makeText(requireContext(), R.string.busy, Toast.LENGTH_LONG).show()
                else attach(started)
            }
        }
    }

    // Progress, confirmation and result.

    private fun attach(task: RspTask?) {
        this.task?.listener = null
        this.task = task
        task?.listener = this
        render(task)
    }

    private fun render(task: RspTask?) {
        val running = task != null && task.outcome == null
        add.isEnabled = !running
        more.isEnabled = !running
        status.isVisible = running
        stop.isVisible = running && task!!.cancellable
        if (task == null) return
        if (running) {
            status.title = stepText(task)
            val request = task.confirmRequest
            if (request != null && request !== shownConfirm) showConfirm(task, request)
            if (request == null && shownConfirm != null) {
                confirmDialog?.dismiss()
                confirmDialog = null
                shownConfirm = null
            }
            return
        }
        val outcome = task.outcome!!
        if (outcome !== shownOutcome) {
            shownOutcome = outcome
            showOutcome(task, outcome)
        }
    }

    private fun stepText(task: RspTask): String = when (task.step) {
        null, Step.READING_EUICC -> getString(R.string.step_reading)
        Step.CONNECTING -> getString(R.string.step_connecting, task.host)
        Step.CHECKING_SERVER -> getString(R.string.step_checking, task.host)
        Step.AUTHENTICATING -> getString(R.string.step_authenticating, task.host)
        Step.CONFIRMING -> getString(R.string.step_confirming)
        Step.PREPARING -> getString(R.string.step_preparing)
        Step.DOWNLOADING -> getString(R.string.step_downloading)
        Step.INSTALLING -> getString(R.string.step_installing)
        Step.NOTIFYING -> getString(R.string.step_notifying)
    }

    /** SGP.22 3.1.3 step 8: what is being downloaded, its rules, the confirmation code. */
    private fun showConfirm(task: RspTask, request: ConfirmRequest) {
        confirmDialog?.dismiss()
        shownConfirm = request
        val context = requireContext()
        val metadata = request.metadata
        val message = TextView(context).apply { text = describe(request) }
        val code = if (request.confirmationCodeRequired) {
            field(context, R.string.confirm_code_hint,
                InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD)
        } else {
            null
        }
        val dialog = AlertDialog.Builder(context)
            .setTitle(getString(R.string.confirm_title, name(metadata)))
            .setView(if (code != null) column(context, message, code) else column(context, message))
            .setPositiveButton(R.string.confirm_download) { _, _ ->
                task.answer(Confirmation.Accept(code?.text?.toString()))
            }
            .setNegativeButton(R.string.confirm_not_now) { _, _ -> task.answer(Confirmation.Decline) }
            .setCancelable(false)
            .create()
        if (code != null) {
            dialog.setOnShowListener {
                val button = dialog.getButton(AlertDialog.BUTTON_POSITIVE)
                button.isEnabled = false
                code.addTextChangedListener(object : TextWatcher {
                    override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                    override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
                    override fun afterTextChanged(s: Editable?) {
                        button.isEnabled = ConfirmationCode.normalise(s?.toString()) != null
                    }
                })
            }
        }
        confirmDialog = dialog
        dialog.window?.let(::secure)
        dialog.show()
    }

    private fun describe(request: ConfirmRequest): String {
        val m = request.metadata
        val lines = mutableListOf(getString(R.string.confirm_from, request.host))
        if (m.serviceProviderName.isNotBlank()) lines += getString(R.string.confirm_provider, m.serviceProviderName.trim())
        if (m.profileName.isNotBlank()) lines += getString(R.string.confirm_name, m.profileName.trim())
        when (m.profileClass) {
            ProfileMetadata.CLASS_TEST -> lines += getString(R.string.class_testing)
            ProfileMetadata.CLASS_PROVISIONING -> lines += getString(R.string.class_provisioning)
        }
        if (m.ppr1) lines += getString(R.string.confirm_ppr1)
        if (m.ppr2) lines += getString(R.string.confirm_ppr2)
        if (request.pprConsentRequired) lines += getString(R.string.confirm_ppr_consent)
        val events = listOf(
            NotificationEvents.INSTALL to R.string.event_install, NotificationEvents.ENABLE to R.string.event_enable,
            NotificationEvents.DISABLE to R.string.event_disable, NotificationEvents.DELETE to R.string.event_delete,
        ).filter { m.notifiedEvents and it.first != 0 }.map { getString(it.second) }
        if (events.isNotEmpty()) lines += getString(R.string.confirm_notified, events.joinToString(", "))
        lines += getString(R.string.confirm_off)
        if (request.confirmationCodeRequired) lines += getString(R.string.confirm_code_needed)
        return lines.joinToString("\n\n")
    }

    private fun name(metadata: ProfileMetadata): String = listOf(metadata.profileName, metadata.serviceProviderName)
        .firstOrNull { it.isNotBlank() }?.trim() ?: getString(R.string.unnamed_profile)

    private fun showOutcome(task: RspTask, outcome: Outcome) {
        confirmDialog?.dismiss()
        confirmDialog = null
        shownConfirm = null
        val context = requireContext()
        if (outcome is Outcome.Found && outcome.events.isNotEmpty()) {
            RspTasks.dismiss(task)
            val events = outcome.events
            AlertDialog.Builder(context)
                .setTitle(R.string.search_found)
                .setItems(events.map { it.rspServerAddress }.toTypedArray()) { _, which ->
                    ActivationCode.fromEvent(events[which].rspServerAddress, events[which].eventId)
                        ?.let { consent(it, RspTask.Kind.DOWNLOAD) }
                }
                .setNegativeButton(android.R.string.cancel, null)
                .show()
            return
        }
        val (title, text) = when (outcome) {
            is Outcome.Installed -> getString(R.string.done_title) to
                getString(if (outcome.notified) R.string.done_text else R.string.done_text_unsent)
            is Outcome.Checked -> getString(R.string.checked_title) to
                getString(R.string.checked_text, task.host, outcome.serverCi, outcome.svn.toString())
            is Outcome.Found -> getString(R.string.search_none_title) to getString(R.string.search_none_text)
            Outcome.Cancelled -> getString(R.string.stopped_title) to getString(R.string.stopped_text)
            is Outcome.Failed -> getString(R.string.failed_title) to failureText(task, outcome.error)
        }
        AlertDialog.Builder(context)
            .setTitle(title)
            .setMessage(text)
            .setPositiveButton(android.R.string.ok) { _, _ ->
                RspTasks.dismiss(task)
                attach(null)
                if (outcome is Outcome.Installed) {
                    clearUsedCode()
                    activity?.finish()
                }
            }
            .setCancelable(false)
            .show()
    }

    private fun failureText(task: RspTask, e: RspException): String {
        val host = task.host
        return when (e.failure) {
            Failure.EUICC_MISSING -> getString(R.string.no_euicc)
            Failure.NO_TRUSTED_CI -> getString(R.string.fail_no_ci)
            Failure.CARD -> getString(R.string.fail_card, e.cardCode ?: 0)
            Failure.CARD_REFUSED_SERVER -> getString(R.string.fail_card_refused_server, host, e.cardCode ?: 0)
            Failure.NETWORK -> getString(R.string.fail_network, host)
            Failure.TLS -> getString(R.string.fail_tls, host)
            Failure.HTTP_STATUS, Failure.INVALID_RESPONSE -> getString(R.string.fail_response, host)
            Failure.SERVER_REFUSED -> serverRefused(host, e)
            Failure.SERVER_MISMATCH, Failure.OID_MISMATCH -> getString(R.string.fail_mismatch, host)
            Failure.CONFIRMATION_CODE_MISSING -> getString(R.string.fail_code_missing)
            Failure.PPR_NOT_ALLOWED -> getString(R.string.fail_ppr)
            Failure.INSTALL_FAILED -> when (e.cardCode) {
                INSTALL_ICCID_EXISTS -> getString(R.string.fail_install_exists)
                INSTALL_NO_MEMORY -> getString(R.string.fail_install_memory)
                else -> getString(R.string.fail_install, e.cardCode ?: 0)
            }
            Failure.USER_TIMEOUT -> getString(R.string.fail_timeout)
            Failure.BUSY -> getString(R.string.busy)
            Failure.NOT_CONSENTED, Failure.FRAMEWORK -> getString(R.string.fail_framework)
        }
    }

    /** SGP.22 5.2.6 subject codes of the common refusals; the codes themselves are public. */
    private fun serverRefused(host: String, e: RspException): String {
        val codes = getString(R.string.fail_codes, e.subjectCode ?: "?", e.reasonCode ?: "?")
        val reason = when {
            e.subjectCode == "8.2.6" -> getString(R.string.refused_code)
            e.subjectCode == "8.2.7" -> getString(R.string.refused_confirmation)
            e.subjectCode == "8.8.5" -> getString(R.string.refused_order)
            e.subjectCode == "8.2" || e.subjectCode == "8.2.5" -> getString(R.string.refused_profile)
            e.subjectCode?.startsWith("8.1") == true -> getString(R.string.refused_euicc)
            else -> getString(R.string.refused_other)
        }
        return getString(R.string.fail_refused, host, reason) + "\n\n" + codes
    }

    private fun invalid(e: ActivationCode.Invalid) {
        val text = when (e.problem) {
            ActivationCode.Problem.ADDRESS -> R.string.invalid_address
            ActivationCode.Problem.TOKEN -> R.string.invalid_token
            ActivationCode.Problem.VERSION -> R.string.invalid_version
            else -> R.string.invalid_code
        }
        Toast.makeText(requireContext(), text, Toast.LENGTH_LONG).show()
    }

    // Helpers.

    private fun clipboardText(): String? = try {
        val clipboard = requireContext().getSystemService(ClipboardManager::class.java)
        clipboard?.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(requireContext())?.toString()
    } catch (e: SecurityException) {
        null
    }

    /** After a download, a copied code is used up: clear it from the clipboard. */
    private fun clearUsedCode() {
        val used = usedCode ?: return
        try {
            val clipboard = appContext.getSystemService(ClipboardManager::class.java) ?: return
            val now = clipboard.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(appContext)?.toString()?.trim()
            if (now == used) clipboard.clearPrimaryClip()
        } catch (e: SecurityException) {
            // Not in the foreground: leave it.
        }
        usedCode = null
    }

    /** Dialogs have their own windows: keep the codes in them out of screenshots too. */
    private fun AlertDialog.Builder.showSecure(): AlertDialog = create().also {
        it.window?.let(::secure)
        it.show()
    }

    private fun action(title: Int, summary: Int, onClick: () -> Unit) = Preference(preferenceManager.context).apply {
        this.title = getString(title)
        if (summary != 0) this.summary = getString(summary)
        setOnPreferenceClickListener {
            onClick()
            true
        }
    }

    /** A text field that keyboards and autofill do not learn from. */
    private fun field(context: Context, hintRes: Int, variation: Int) = EditText(context).apply {
        hint = getString(hintRes)
        isSingleLine = true
        inputType = InputType.TYPE_CLASS_TEXT or variation or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
    }

    private fun column(context: Context, vararg views: View): View {
        val padding = (24 * resources.displayMetrics.density).toInt()
        return LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(padding, padding / 2, padding, 0)
            views.forEach { addView(it) }
        }
    }

    companion object {
        private const val STATE_SCAN = "awaiting_scan"

        /**
         * No screenshots or recents preview, and no other apps' overlays over the window while
         * it shows (any app can open this screen with a code through OpenCodeActivity).
         */
        fun secure(window: Window) {
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
            window.setHideOverlayWindows(true)
        }

        // SGP.22 ErrorReason (2.5.6).
        private const val INSTALL_ICCID_EXISTS = 9
        private const val INSTALL_NO_MEMORY = 10
    }
}
