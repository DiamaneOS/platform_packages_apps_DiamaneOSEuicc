// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc.download

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.service.euicc.DownloadSubscriptionResult
import android.telephony.TelephonyManager
import android.telephony.euicc.DownloadableSubscription
import android.telephony.euicc.EuiccManager
import android.util.Log
import de.diamaneos.euicc.card.CardClient
import de.diamaneos.euicc.card.Euicc
import de.diamaneos.euicc.card.RspCardAdapter
import de.diamaneos.euicc.core.ActivationCode
import de.diamaneos.euicc.core.ConfirmRequest
import de.diamaneos.euicc.core.Confirmation
import de.diamaneos.euicc.core.DownloadFlow
import de.diamaneos.euicc.core.Failure
import de.diamaneos.euicc.core.NotificationFlow
import de.diamaneos.euicc.core.Outcome
import de.diamaneos.euicc.core.Results
import de.diamaneos.euicc.core.RspException
import de.diamaneos.euicc.core.RspUser
import de.diamaneos.euicc.core.Step
import de.diamaneos.euicc.net.PinnedServers
import java.security.SecureRandom
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.ReentrantLock

/**
 * One download, dry run or SM-DS search the user started on this app's screen. The screen
 * shows it; the flow asks it for the confirmation and whether to stop. Survives the screen
 * (rotation, leaving it); the confirmation times out after [CONFIRM_TIMEOUT_MIN] minutes.
 */
class RspTask(val kind: Kind, val euicc: Euicc, val host: String, val code: ActivationCode?) : RspUser {
    enum class Kind { DOWNLOAD, CHECK, SEARCH }

    /** Called on the main thread whenever the task changes. */
    fun interface Listener {
        fun onTaskChanged(task: RspTask)
    }

    /** Pairs the framework's result broadcast with this task. */
    internal val token: Long = SecureRandom().nextLong()
    private val stop = AtomicBoolean()
    private val answered = CountDownLatch(1)

    @Volatile private var answer: Confirmation? = null

    @Volatile var step: Step? = null
        private set

    @Volatile var outcome: Outcome? = null
        private set

    /** The pending confirmation, while the flow waits for it. */
    @Volatile var confirmRequest: ConfirmRequest? = null
        private set

    /** Set and read on the main thread. */
    var listener: Listener? = null

    @Volatile internal var started = false

    override val cancelled: Boolean get() = stop.get()

    /** Until the package download starts, stopping keeps the code usable. */
    val cancellable: Boolean
        get() = outcome == null && !stop.get() && (step?.let { it <= Step.PREPARING } ?: true)

    override fun step(step: Step) {
        this.step = step
        changed()
    }

    override fun confirm(request: ConfirmRequest): Confirmation? {
        confirmRequest = request
        changed()
        val ok = try {
            answered.await(CONFIRM_TIMEOUT_MIN, TimeUnit.MINUTES)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            false
        }
        confirmRequest = null
        changed()
        // The answer may hold the confirmation code: hand it over once, keep nothing.
        val result = if (ok) answer else null
        answer = null
        return result
    }

    /** The user's answer to [confirmRequest]. */
    fun answer(confirmation: Confirmation) {
        if (confirmRequest == null) return
        answer = confirmation
        answered.countDown()
    }

    fun cancel() {
        if (!cancellable) return
        stop.set(true)
        answer(Confirmation.Decline)
        changed()
    }

    internal fun finish(outcome: Outcome) {
        if (this.outcome != null) return
        this.outcome = outcome
        changed()
    }

    private fun changed() {
        MAIN.post { listener?.onTaskChanged(this) }
    }

    companion object {
        const val CONFIRM_TIMEOUT_MIN = 5L
        private val MAIN = Handler(Looper.getMainLooper())
    }
}

/**
 * Starts and runs RSP tasks, one at a time, and sends notifications after profile changes.
 * - A download goes through EuiccManager.downloadSubscription, so the framework does its
 *   bookkeeping (refresh, EUICC_PROVISIONED for a later reset); the framework then calls this
 *   app's EuiccService, which runs the flow only for the task the user started here ([serve]).
 * - A dry run or a search runs here directly; neither downloads anything.
 * - [cardSession] serialises every RSP session and notification sending: a new
 *   GetEUICCChallenge would end a running session on the eUICC.
 * Logs steps and results only, never a host, code or identifier.
 */
object RspTasks {
    private val cardSession = ReentrantLock()
    private val worker = Executors.newSingleThreadExecutor()

    @Volatile var current: RspTask? = null
        private set

    private val running: Boolean get() = current?.let { it.outcome == null } ?: false

    /** Null if another task is running. */
    @Synchronized
    fun startDownload(context: Context, euicc: Euicc, code: ActivationCode): RspTask? {
        if (running) return null
        val task = RspTask(RspTask.Kind.DOWNLOAD, euicc, code.smdpAddress, code)
        current = task
        val app = context.applicationContext
        worker.execute {
            val manager = app.getSystemService(EuiccManager::class.java)
            if (manager == null || !manager.isEnabled) {
                task.finish(failed(Failure.EUICC_MISSING))
                return@execute
            }
            val intent = Intent(app, DownloadResultReceiver::class.java)
                .setAction(DownloadResultReceiver.ACTION)
                .putExtra(DownloadResultReceiver.EXTRA_TOKEN, task.token)
            // Mutable so the framework can add its result extras; explicit, so nothing else gets it.
            val callback = PendingIntent.getBroadcast(app, 0, intent,
                PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_ONE_SHOT or PendingIntent.FLAG_UPDATE_CURRENT)
            try {
                // Never switch after the download: turning a profile on is a separate choice.
                manager.downloadSubscription(DownloadableSubscription.forActivationCode(code.encoded()), false, callback)
                Log.i(TAG, "download: requested")
            } catch (e: RuntimeException) {
                Log.w(TAG, "download: request failed ${e.javaClass.simpleName}")
                task.finish(failed(Failure.FRAMEWORK))
            }
        }
        return task
    }

    /** Dry run of [code] (DownloadFlow.check). Null if another task is running. */
    @Synchronized
    fun startCheck(context: Context, euicc: Euicc, code: ActivationCode): RspTask? {
        if (running) return null
        val task = RspTask(RspTask.Kind.CHECK, euicc, code.smdpAddress, code)
        current = task
        run(context, task) { it.check(code) }
        return task
    }

    /** SM-DS event retrieval at [smdsHost] (DownloadFlow.discover). Null if another task is running. */
    @Synchronized
    fun startSearch(context: Context, euicc: Euicc, smdsHost: String): RspTask? {
        if (running) return null
        val task = RspTask(RspTask.Kind.SEARCH, euicc, smdsHost, null)
        current = task
        run(context, task) { it.discover(smdsHost) }
        return task
    }

    /** The screen is done with a finished task. */
    @Synchronized
    fun dismiss(task: RspTask) {
        if (current === task && task.outcome != null) current = null
    }

    /**
     * EuiccService.onDownloadSubscription. Runs only the download the user started and
     * confirmed on this app's screen: same package, same code, same eUICC, not switching.
     * Anything else (another app's request, a stale one) is refused without card or network use.
     */
    fun serve(
        context: Context,
        slotIndex: Int,
        subscription: DownloadableSubscription,
        switchAfterDownload: Boolean,
        resolvedBundle: Bundle?,
    ): DownloadSubscriptionResult {
        val task = current
        val caller = resolvedBundle?.getString(EXTRA_PACKAGE_NAME)
        if (task == null || task.kind != RspTask.Kind.DOWNLOAD || task.outcome != null || task.started ||
            caller != context.packageName || switchAfterDownload ||
            subscription.encodedActivationCode != task.code?.encoded()) {
            Log.w(TAG, "download: refused, not started on this screen")
            return result(Results.error(Results.OPERATION_DOWNLOAD, Results.DETAIL_NOT_CONSENTED))
        }
        task.started = true
        val client = CardClient(context)
        // Check the slot first: a card call to a missing card logs its EID (-176).
        if (client.euicc(slotIndex)?.cardId != task.euicc.cardId) {
            return finish(task, failed(Failure.EUICC_MISSING))
        }
        if (!cardSession.tryLock(LOCK_WAIT_S, TimeUnit.SECONDS)) return finish(task, failed(Failure.BUSY))
        val outcome = try {
            flow(context, client, task).download(task.code!!)
        } catch (e: RuntimeException) {
            Log.w(TAG, "download: ${e.javaClass.simpleName}")
            failed(Failure.FRAMEWORK)
        } finally {
            cardSession.unlock()
        }
        return finish(task, outcome)
    }

    /** The framework's result for [token]; settles a task the service never ran. */
    fun onFrameworkResult(token: Long, resultCode: Int, detailedCode: Int) {
        val task = current ?: return
        if (task.token != token || task.outcome != null || task.started) return
        // The service settles every task it runs before the framework answers, so this one never
        // reached it: the framework refused it or lost the service.
        Log.i(TAG, "download: framework result=$resultCode detail=$detailedCode")
        task.finish(failed(Failure.FRAMEWORK))
    }

    /**
     * After a profile change: sends the pending notifications of profiles this app installed
     * (NotificationFlow), in the background. Waits until the eUICC is back after its restart;
     * gives up quietly if another session holds the card; the rest stays queued.
     */
    fun sendNotificationsAsync(context: Context, euicc: Euicc) {
        val app = context.applicationContext
        worker.execute {
            val owned = OwnedProfiles.load(app) ?: return@execute
            if (owned.size == 0) return@execute
            val client = CardClient(app)
            if (!waitForCard(client, euicc)) {
                Log.i(TAG, "notifications: eUICC not back, kept")
                return@execute
            }
            if (!cardSession.tryLock(LOCK_WAIT_S, TimeUnit.SECONDS)) return@execute
            try {
                val summary = notifications(app, client, euicc).sendOwned()
                Log.i(TAG, "notifications: $summary")
            } catch (e: Exception) {
                Log.w(TAG, "notifications: ${e.javaClass.simpleName}")
            } finally {
                cardSession.unlock()
            }
        }
    }

    /** The notification flow for the screen's list; call on a worker thread, not during a task. */
    fun <T> withNotifications(context: Context, euicc: Euicc, block: (NotificationFlow) -> T): T? {
        val app = context.applicationContext
        if (!cardSession.tryLock(LOCK_WAIT_S, TimeUnit.SECONDS)) return null
        return try {
            block(notifications(app, CardClient(app), euicc))
        } catch (e: Exception) {
            Log.w(TAG, "notifications: ${e.javaClass.simpleName}")
            null
        } finally {
            cardSession.unlock()
        }
    }

    private fun run(context: Context, task: RspTask, body: (DownloadFlow) -> Outcome) {
        val app = context.applicationContext
        worker.execute {
            val outcome = if (!cardSession.tryLock(LOCK_WAIT_S, TimeUnit.SECONDS)) {
                failed(Failure.BUSY)
            } else {
                try {
                    val client = CardClient(app)
                    if (client.euicc(task.euicc.slot)?.cardId != task.euicc.cardId) failed(Failure.EUICC_MISSING)
                    else body(flow(app, client, task))
                } catch (e: RuntimeException) {
                    Log.w(TAG, "${task.kind}: ${e.javaClass.simpleName}")
                    failed(Failure.FRAMEWORK)
                } finally {
                    cardSession.unlock()
                }
            }
            log(task, outcome)
            task.finish(outcome)
        }
    }

    private fun flow(context: Context, client: CardClient, task: RspTask) = DownloadFlow(
        card = RspCardAdapter(client, task.euicc),
        servers = PinnedServers(CiRoots.get(context)),
        user = LoggingUser(task),
        installed = { iccid -> OwnedProfiles.add(context, iccid) },
    )

    private fun notifications(context: Context, client: CardClient, euicc: Euicc) = NotificationFlow(
        card = RspCardAdapter(client, euicc),
        servers = PinnedServers(CiRoots.get(context)),
        owned = { OwnedProfiles.contains(context, it) },
        forget = { OwnedProfiles.remove(context, it) },
    )

    private fun finish(task: RspTask, outcome: Outcome): DownloadSubscriptionResult {
        log(task, outcome)
        task.finish(outcome)
        return result(Results.fromOutcome(outcome))
    }

    private fun result(code: Int) = DownloadSubscriptionResult(code, 0, TelephonyManager.UNSUPPORTED_CARD_ID)

    private fun waitForCard(client: CardClient, euicc: Euicc): Boolean {
        repeat(CARD_WAIT_ATTEMPTS) { attempt ->
            if (client.euicc(euicc.slot)?.cardId == euicc.cardId) return true
            if (attempt < CARD_WAIT_ATTEMPTS - 1) Thread.sleep(CARD_WAIT_MS)
        }
        return false
    }

    private fun log(task: RspTask, outcome: Outcome) {
        val text = when (outcome) {
            is Outcome.Failed -> "failed ${outcome.failure} card=${outcome.error.cardCode} " +
                "subject=${outcome.error.subjectCode} reason=${outcome.error.reasonCode}"
            is Outcome.Installed -> "installed notified=${outcome.notified}"
            is Outcome.Checked -> "checked ci=${outcome.serverCi} svn=${outcome.svn}"
            is Outcome.Found -> "found events=${outcome.events.size}"
            Outcome.Cancelled -> "cancelled"
        }
        Log.i(TAG, "${task.kind.name.lowercase()}: $text")
    }

    private fun failed(failure: Failure) = Outcome.Failed(RspException(failure))

    /** The task, with each step logged by name. */
    private class LoggingUser(private val task: RspTask) : RspUser by task {
        override fun step(step: Step) {
            Log.i(TAG, "${task.kind.name.lowercase()}: step ${step.name}")
            task.step(step)
        }
    }

    /** EuiccService.EXTRA_PACKAGE_NAME (hidden): EuiccController puts the calling package here. */
    private const val EXTRA_PACKAGE_NAME = "android.service.euicc.extra.PACKAGE_NAME"
    private const val LOCK_WAIT_S = 10L
    private const val CARD_WAIT_ATTEMPTS = 15
    private const val CARD_WAIT_MS = 1500L
    private const val TAG = "DiamaneOSEuicc"
}

/** EuiccManager.downloadSubscription's result for a task (explicit, not exported). */
class DownloadResultReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ACTION) return
        RspTasks.onFrameworkResult(
            intent.getLongExtra(EXTRA_TOKEN, 0),
            resultCode,
            intent.getIntExtra(EuiccManager.EXTRA_EMBEDDED_SUBSCRIPTION_DETAILED_CODE, 0),
        )
    }

    companion object {
        const val ACTION = "de.diamaneos.euicc.action.DOWNLOAD_RESULT"
        const val EXTRA_TOKEN = "de.diamaneos.euicc.extra.TOKEN"
    }
}
