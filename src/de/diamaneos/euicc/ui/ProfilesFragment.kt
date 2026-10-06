// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.ui

import android.app.AlertDialog
import android.content.Context
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.UserManager
import android.telephony.SubscriptionManager
import android.text.InputFilter
import android.util.Log
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.Toast
import androidx.preference.Preference
import androidx.preference.PreferenceCategory
import androidx.preference.PreferenceFragmentCompat
import de.diamaneos.euicc.R
import de.diamaneos.euicc.card.CardClient
import de.diamaneos.euicc.card.CardResult
import de.diamaneos.euicc.card.Euicc
import de.diamaneos.euicc.card.ProfileOperations
import de.diamaneos.euicc.card.Profiles
import de.diamaneos.euicc.core.Nickname
import de.diamaneos.euicc.core.Profile
import de.diamaneos.euicc.core.ProfileClass
import de.diamaneos.euicc.core.ProfileList
import de.diamaneos.euicc.core.Results
import java.util.concurrent.Executors

/**
 * The profiles on the eUICC: the EID (hidden until tapped), then one row per profile. A row
 * offers turn on or off, rename and delete, each confirmed. Card calls run on a worker thread;
 * nothing is stored or logged.
 */
class ProfilesFragment : PreferenceFragmentCompat() {
    private val worker = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private lateinit var appContext: Context
    private lateinit var client: CardClient
    private lateinit var operations: ProfileOperations
    private lateinit var eid: Preference
    private lateinit var category: PreferenceCategory
    private var euicc: Euicc? = null
    private var eidShown = false
    private var busy = false

    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        val context = preferenceManager.context
        appContext = context.applicationContext
        client = CardClient(appContext)
        operations = ProfileOperations(client)
        preferenceScreen = preferenceManager.createPreferenceScreen(context)
        eid = Preference(context).apply {
            title = getString(R.string.eid_title)
            isVisible = false
            setOnPreferenceClickListener {
                eidShown = !eidShown
                updateEid()
                true
            }
        }
        category = PreferenceCategory(context).apply { title = getString(R.string.profiles_title) }
        preferenceScreen.addPreference(eid)
        preferenceScreen.addPreference(category)
    }

    override fun onResume() {
        super.onResume()
        if (!busy) reload()
    }

    override fun onDestroy() {
        worker.shutdown()
        super.onDestroy()
    }

    private fun reload() {
        busy = true
        showStatus(R.string.loading)
        worker.execute {
            val found = client.defaultEuicc()
            val result = found?.let { client.profiles(it) }
            main.post { if (isAdded) show(found, result) }
        }
    }

    private fun show(found: Euicc?, result: CardResult<Profiles>?) {
        euicc = found
        busy = false
        eid.isVisible = found != null
        updateEid()
        val list = result?.value?.list
        when {
            found == null -> showStatus(R.string.no_euicc)
            list == null -> showStatus(R.string.card_error)
            list.profiles.isEmpty() -> showStatus(R.string.no_profiles)
            else -> {
                category.removeAll()
                list.forDisplay().forEach { category.addPreference(row(it, list)) }
            }
        }
    }

    private fun showStatus(text: Int) {
        category.removeAll()
        category.addPreference(Preference(preferenceManager.context).apply {
            title = getString(text)
            isSelectable = false
        })
    }

    private fun updateEid() {
        val id = euicc?.cardId
        eid.summary = if (eidShown && id != null) {
            id.chunked(4).joinToString(" ")
        } else {
            getString(R.string.eid_hidden)
        }
    }

    private fun row(profile: Profile, list: ProfileList) = Preference(preferenceManager.context).apply {
        title = name(profile)
        summary = summary(profile)
        // Admins can block changes to mobile networks, as for Settings' SIM pages.
        isEnabled = !requireContext().getSystemService(UserManager::class.java)
            .hasUserRestriction(UserManager.DISALLOW_CONFIG_MOBILE_NETWORKS)
        setOnPreferenceClickListener {
            if (!busy) showActions(profile, list)
            true
        }
    }

    private fun name(profile: Profile) = profile.displayName ?: getString(R.string.unnamed_profile)

    private fun summary(profile: Profile): String {
        val parts = mutableListOf(getString(if (profile.isEnabled) R.string.state_on else R.string.state_off))
        val provider = profile.providerName?.trim()
        if (!provider.isNullOrEmpty() && provider != profile.displayName) parts += provider
        when (profile.profileClass) {
            ProfileClass.TESTING -> parts += getString(R.string.class_testing)
            ProfileClass.PROVISIONING -> parts += getString(R.string.class_provisioning)
            ProfileClass.OPERATIONAL -> {}
        }
        return parts.joinToString(" · ")
    }

    private fun showActions(profile: Profile, list: ProfileList) {
        val actions = mutableListOf<Pair<Int, () -> Unit>>()
        val current = list.enabled
        if (profile.isEnabled) {
            if (profile.mayDisable) actions += R.string.action_turn_off to { confirmTurnOff(profile) }
        } else if (current == null || current.mayDisable) {
            actions += R.string.action_turn_on to { confirmTurnOn(profile, current) }
        }
        actions += R.string.action_rename to { rename(profile) }
        if (profile.mayDelete && (!profile.isEnabled || profile.mayDisable)) {
            actions += R.string.action_delete to { confirmDelete(profile) }
        }
        AlertDialog.Builder(requireContext())
            .setTitle(name(profile))
            .setItems(actions.map { getString(it.first) }.toTypedArray()) { _, which ->
                actions[which].second()
            }
            .show()
    }

    private fun confirmTurnOn(profile: Profile, current: Profile?) {
        val builder = AlertDialog.Builder(requireContext())
            .setTitle(getString(R.string.turn_on_title, name(profile)))
            .setPositiveButton(R.string.action_turn_on) { _, _ ->
                change { operations.switch(it, 0, profile.iccid, true) }
            }
            .setNegativeButton(android.R.string.cancel, null)
        if (current != null) builder.setMessage(getString(R.string.turn_on_text_switch, name(current)))
        builder.show()
    }

    private fun confirmTurnOff(profile: Profile) {
        var text = getString(R.string.turn_off_text)
        if (profile.deletedWhenDisabled) text += "\n\n" + getString(R.string.turn_off_text_deleted)
        AlertDialog.Builder(requireContext())
            .setTitle(getString(R.string.turn_off_title, name(profile)))
            .setMessage(text)
            .setPositiveButton(R.string.action_turn_off) { _, _ ->
                change { operations.disable(it, profile.iccid) }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun rename(profile: Profile) {
        val context = requireContext()
        val input = EditText(context).apply {
            setText(profile.nickname.orEmpty())
            setSelection(text.length)
            isSingleLine = true
            hint = getString(R.string.rename_hint)
            filters = arrayOf(InputFilter.LengthFilter(Nickname.MAX_BYTES))
        }
        val padding = (24 * resources.displayMetrics.density).toInt()
        val frame = FrameLayout(context).apply {
            setPadding(padding, padding / 2, padding, 0)
            addView(input)
        }
        AlertDialog.Builder(context)
            .setTitle(R.string.rename_title)
            .setView(frame)
            .setPositiveButton(R.string.rename_save) { _, _ ->
                val nickname = input.text.toString()
                if (Nickname.normalise(nickname) == null) {
                    Toast.makeText(context, R.string.rename_invalid, Toast.LENGTH_LONG).show()
                } else {
                    change { operations.rename(it, profile.iccid, nickname) }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun confirmDelete(profile: Profile) {
        var text = getString(R.string.delete_text)
        if (profile.isEnabled) text += "\n\n" + getString(R.string.delete_text_enabled)
        AlertDialog.Builder(requireContext())
            .setTitle(getString(R.string.delete_title, name(profile)))
            .setMessage(text)
            .setPositiveButton(R.string.action_delete) { _, _ ->
                change { operations.delete(it, profile.iccid) }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /** Runs a profile change, asks the framework to re-read the profiles, then reloads. */
    private fun change(operation: (Euicc) -> Int) {
        val target = euicc ?: return
        busy = true
        showStatus(R.string.working)
        worker.execute {
            val result = operation(target)
            if (result == Results.OK) refreshFramework()
            main.post {
                if (!isAdded) return@post
                if (result != Results.OK) {
                    Toast.makeText(requireContext(), R.string.failed, Toast.LENGTH_LONG).show()
                }
                reload()
            }
        }
    }

    /** The framework re-reads profiles itself after its own requests, not after ours. */
    private fun refreshFramework() {
        try {
            appContext.getSystemService(SubscriptionManager::class.java)
                ?.requestEmbeddedSubscriptionInfoListRefresh()
        } catch (e: RuntimeException) {
            Log.w(TAG, "subscription refresh failed: ${e.javaClass.simpleName}")
        }
    }

    private companion object {
        const val TAG = "DiamaneOSEuicc"
    }
}
