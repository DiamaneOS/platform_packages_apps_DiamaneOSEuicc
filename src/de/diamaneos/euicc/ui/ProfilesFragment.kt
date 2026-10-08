// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.ui

import android.app.AlertDialog
import android.content.Context
import android.content.Intent
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
import de.diamaneos.euicc.core.NotificationEvents
import de.diamaneos.euicc.core.NotificationFlow
import de.diamaneos.euicc.core.Nickname
import de.diamaneos.euicc.core.Profile
import de.diamaneos.euicc.core.ProfileClass
import de.diamaneos.euicc.core.ProfileList
import de.diamaneos.euicc.core.Results
import de.diamaneos.euicc.download.RspTasks
import java.util.concurrent.Executors

/**
 * The profiles on the eUICC: "Add eSIM", the EID (hidden until tapped), then one row per
 * profile. A row offers turn on or off, rename and delete, each confirmed. Below, the carrier
 * notifications the eUICC still holds, to send (profiles added here) or remove. Card calls run
 * on a worker thread; nothing is logged.
 */
class ProfilesFragment : PreferenceFragmentCompat() {
    private val worker = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private lateinit var appContext: Context
    private lateinit var client: CardClient
    private lateinit var operations: ProfileOperations
    private lateinit var addEsim: Preference
    private lateinit var eid: Preference
    private lateinit var category: PreferenceCategory
    private lateinit var notifications: Preference
    private var euicc: Euicc? = null
    private var eidShown = false
    private var busy = false
    private var pendingNotifications: List<NotificationFlow.Entry> = emptyList()

    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        val context = preferenceManager.context
        appContext = context.applicationContext
        client = CardClient(appContext)
        operations = ProfileOperations(client) { RspTasks.sendNotificationsAsync(appContext, it) }
        preferenceScreen = preferenceManager.createPreferenceScreen(context)
        addEsim = Preference(context).apply {
            title = getString(R.string.add_title)
            summary = getString(R.string.add_summary)
            setOnPreferenceClickListener {
                startActivity(Intent(context, AddEsimActivity::class.java))
                true
            }
        }
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
        notifications = Preference(context).apply {
            title = getString(R.string.notifications_title)
            isVisible = false
            setOnPreferenceClickListener {
                if (!busy) showNotifications()
                true
            }
        }
        preferenceScreen.addPreference(addEsim)
        preferenceScreen.addPreference(eid)
        preferenceScreen.addPreference(category)
        preferenceScreen.addPreference(notifications)
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
            val pending = found?.let { e -> RspTasks.withNotifications(appContext, e) { it.list() } }
            main.post { if (isAdded) show(found, result, pending) }
        }
    }

    private fun show(found: Euicc?, result: CardResult<Profiles>?, pending: List<NotificationFlow.Entry>?) {
        euicc = found
        busy = false
        eid.isVisible = found != null
        addEsim.isEnabled = found != null && !restricted()
        updateEid()
        pendingNotifications = pending.orEmpty()
        notifications.isVisible = pendingNotifications.isNotEmpty()
        notifications.summary = resources.getQuantityString(R.plurals.notifications_summary,
            pendingNotifications.size, pendingNotifications.size)
        val list = result?.value?.list
        when {
            found == null -> showStatus(R.string.no_euicc)
            list == null -> showStatus(R.string.card_error)
            list.visible.isEmpty() -> showStatus(R.string.no_profiles)
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
        isEnabled = !restricted()
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
        if (current != null) {
            var text = getString(R.string.turn_on_text_switch, name(current))
            if (current.deletedWhenDisabled) {
                text += "\n\n" + getString(R.string.turn_on_text_switch_deleted, name(current))
            }
            builder.setMessage(text)
        }
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

    private fun restricted() = requireContext().getSystemService(UserManager::class.java)
        .hasUserRestriction(UserManager.DISALLOW_CONFIG_MOBILE_NETWORKS)

    /**
     * The eUICC's pending notifications (SGP.22 3.5): event and server only. Those of profiles
     * added here can be sent; any can be removed. Sending happens on its own after changes.
     */
    private fun showNotifications() {
        val entries = pendingNotifications
        if (entries.isEmpty()) return
        val labels = entries.map { n ->
            getString(R.string.notification_item, eventName(n.event), n.address) +
                if (n.ours) "\n" + getString(R.string.notification_ours) else ""
        }
        AlertDialog.Builder(requireContext())
            .setTitle(R.string.notifications_title)
            .setItems(labels.toTypedArray()) { _, which -> notificationActions(entries[which]) }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun notificationActions(entry: NotificationFlow.Entry) {
        val builder = AlertDialog.Builder(requireContext())
            .setTitle(getString(R.string.notification_item, eventName(entry.event), entry.address))
            .setMessage(if (entry.ours) R.string.notification_text_ours else R.string.notification_text_other)
            .setNeutralButton(android.R.string.cancel, null)
            .setNegativeButton(R.string.notification_remove) { _, _ ->
                notificationChange { it.remove(entry.seq); true }
            }
        if (entry.ours && !restricted()) {
            builder.setPositiveButton(R.string.notification_send) { _, _ -> notificationChange { it.send(entry.seq) } }
        }
        builder.show()
    }

    private fun notificationChange(change: (NotificationFlow) -> Boolean) {
        val target = euicc ?: return
        busy = true
        showStatus(R.string.working)
        worker.execute {
            val ok = RspTasks.withNotifications(appContext, target, change) == true
            main.post {
                if (!isAdded) return@post
                if (!ok) Toast.makeText(requireContext(), R.string.failed, Toast.LENGTH_LONG).show()
                reload()
            }
        }
    }

    private fun eventName(event: Int) = getString(when (event) {
        NotificationEvents.INSTALL -> R.string.event_install
        NotificationEvents.ENABLE -> R.string.event_enable
        NotificationEvents.DISABLE -> R.string.event_disable
        else -> R.string.event_delete
    })

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
