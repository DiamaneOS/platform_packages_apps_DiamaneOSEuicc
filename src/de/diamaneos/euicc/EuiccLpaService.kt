// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The DiamaneOS Project

package de.diamaneos.euicc

import android.os.Bundle
import android.service.euicc.DownloadSubscriptionResult
import android.service.euicc.EuiccService
import android.service.euicc.GetDefaultDownloadableSubscriptionListResult
import android.service.euicc.GetDownloadableSubscriptionMetadataResult
import android.service.euicc.GetEuiccProfileInfoListResult
import android.telephony.TelephonyManager
import android.telephony.euicc.DownloadableSubscription
import android.telephony.euicc.EuiccCardManager
import android.telephony.euicc.EuiccInfo
import android.telephony.euicc.EuiccManager
import android.util.Log
import de.diamaneos.euicc.card.CardClient
import de.diamaneos.euicc.card.Euicc
import de.diamaneos.euicc.card.ProfileOperations
import de.diamaneos.euicc.core.EuiccInfo1
import de.diamaneos.euicc.core.EuiccInfo2
import de.diamaneos.euicc.core.GsmaCi
import de.diamaneos.euicc.core.NotificationEvents
import de.diamaneos.euicc.core.PendingNotification
import de.diamaneos.euicc.core.Results
import de.diamaneos.euicc.download.CiRoots
import de.diamaneos.euicc.download.OwnedProfiles
import de.diamaneos.euicc.download.RspTasks
import java.io.PrintWriter

/**
 * The LPA backend the telephony framework binds (EuiccConnector) once the user turns on eSIM
 * support: list, enable, disable, rename, delete, erase, and download the profile the user
 * started on this app's screen (RspTasks.serve). The framework calls these methods on the
 * service's worker threads, so they block on the card. Never logs the EID, an ICCID, an IMSI,
 * a code or a server.
 */
class EuiccLpaService : EuiccService() {
    private lateinit var client: CardClient
    private lateinit var operations: ProfileOperations

    override fun onCreate() {
        super.onCreate()
        client = CardClient(this)
        operations = ProfileOperations(client) { RspTasks.sendNotificationsAsync(this, it) }
    }

    override fun onGetEid(slotId: Int): String? = client.euicc(slotId)?.cardId

    override fun onGetEuiccProfileInfoList(slotId: Int): GetEuiccProfileInfoListResult {
        val euicc = client.euicc(slotId)
            ?: return GetEuiccProfileInfoListResult(Results.EUICC_MISSING, null, false)
        val result = client.profiles(euicc)
        val profiles = result.value
        if (!result.ok || profiles == null) {
            Log.w(TAG, "profile list: card result ${result.code}")
            return GetEuiccProfileInfoListResult(Results.fromCard(result.code), null, euicc.removable)
        }
        Log.i(TAG, "profile list: ${profiles.list.summary()}")
        val infos = profiles.list.profiles.mapNotNull { profiles.infos[it.index] }
        return GetEuiccProfileInfoListResult(Results.OK, infos.toTypedArray(), euicc.removable)
    }

    override fun onGetEuiccInfo(slotId: Int): EuiccInfo {
        val euicc = client.euicc(slotId) ?: return EuiccInfo(null)
        val info2 = client.euiccInfo2(euicc)
        return EuiccInfo(if (info2.ok) EuiccInfo2.firmwareVersion(info2.value) else null)
    }

    @Suppress("OVERRIDE_DEPRECATION")
    override fun onSwitchToSubscription(slotId: Int, iccid: String?, forceDeactivateSim: Boolean) =
        onSwitchToSubscriptionWithPort(slotId, 0, iccid, forceDeactivateSim)

    override fun onSwitchToSubscriptionWithPort(
        slotId: Int,
        portIndex: Int,
        iccid: String?,
        forceDeactivateSim: Boolean,
    ): Int = withEuicc(slotId) { operations.switch(it, portIndex, iccid, forceDeactivateSim) }

    override fun onDeleteSubscription(slotId: Int, iccid: String): Int =
        withEuicc(slotId) { operations.delete(it, iccid) }

    override fun onUpdateSubscriptionNickname(slotId: Int, iccid: String, nickname: String?): Int =
        withEuicc(slotId) { operations.rename(it, iccid, nickname) }

    @Suppress("OVERRIDE_DEPRECATION")
    override fun onEraseSubscriptions(slotId: Int): Int =
        onEraseSubscriptions(slotId, EuiccCardManager.RESET_OPTION_DELETE_OPERATIONAL_PROFILES)

    override fun onEraseSubscriptions(slotIndex: Int, options: Int): Int =
        withEuicc(slotIndex) { operations.erase(it, options) }

    /**
     * The API assumes an LPA that erases profiles on its own on the first boot after a reset
     * unless told to keep them. This one never erases unless asked, so profiles are kept
     * without a stored flag.
     */
    override fun onRetainSubscriptionsForFactoryReset(slotId: Int): Int = Results.OK

    // No eUICC OS updates.
    override fun onGetOtaStatus(slotId: Int): Int = EuiccManager.EUICC_OTA_STATUS_UNAVAILABLE

    override fun onStartOtaIfNecessary(
        slotId: Int,
        statusChangedCallback: EuiccService.OtaStatusChangedCallback,
    ) {
    }

    // Metadata lookups and the default list would contact servers without the user asking on
    // this app's screen: not served. SM-DS discovery is the screen's explicit search.
    override fun onGetDownloadableSubscriptionMetadata(
        slotId: Int,
        subscription: DownloadableSubscription,
        forceDeactivateSim: Boolean,
    ) = GetDownloadableSubscriptionMetadataResult(Results.NOT_SUPPORTED, null)

    override fun onGetDownloadableSubscriptionMetadata(
        slotId: Int,
        portIndex: Int,
        subscription: DownloadableSubscription,
        forceDeactivateSim: Boolean,
    ) = GetDownloadableSubscriptionMetadataResult(Results.NOT_SUPPORTED, null)

    override fun onGetDefaultDownloadableSubscriptionList(slotId: Int, forceDeactivateSim: Boolean) =
        GetDefaultDownloadableSubscriptionListResult(Results.NOT_SUPPORTED, null)

    /** Only the download the user started on this app's screen; see RspTasks.serve. */
    override fun onDownloadSubscription(
        slotIndex: Int,
        portIndex: Int,
        subscription: DownloadableSubscription,
        switchAfterDownload: Boolean,
        forceDeactivateSim: Boolean,
        resolvedBundle: Bundle,
    ): DownloadSubscriptionResult = try {
        RspTasks.serve(this, slotIndex, subscription, switchAfterDownload, resolvedBundle)
    } catch (e: RuntimeException) {
        // An exception here would end the service's worker thread and the process.
        Log.w(TAG, "download: ${e.javaClass.simpleName}")
        DownloadSubscriptionResult(Results.error(Results.OPERATION_SYSTEM, Results.DETAIL_UNKNOWN), 0,
            TelephonyManager.UNSUPPORTED_CARD_ID)
    }

    /**
     * dumpsys econtroller: counts, versions and public CI names only. The eUICC's SGP.22
     * version, capabilities and CI lists decide whether a download can work.
     */
    override fun dump(printWriter: PrintWriter) {
        val euicc = client.defaultEuicc()
        printWriter.println("DiamaneOS eSIM: ${euicc ?: "no eUICC"}")
        if (euicc == null) return
        val result = client.profiles(euicc)
        val profiles = result.value
        printWriter.println(
            if (result.ok && profiles != null) profiles.list.summary()
            else "profile list: card result ${result.code}")
        val info1 = client.euiccInfo1(euicc).value?.let { runCatching { EuiccInfo1.parse(it) }.getOrNull() }
        val info2 = EuiccInfo2.summary(client.euiccInfo2(euicc).value)
        val roots = CiRoots.get(this)
        printWriter.println("EUICCInfo1: svn=${info1?.svn} " +
            "verify=[${info1?.ciForVerification?.joinToString { GsmaCi.describe(it) }}] " +
            "sign=[${info1?.ciForSigning?.joinToString { GsmaCi.describe(it) }}]")
        printWriter.println("EUICCInfo2: svn=${info2?.svn} profileVersion=${info2?.profileVersion} " +
            "firmware=${info2?.firmware} ppVersion=${info2?.ppVersion} category=${info2?.category} " +
            "capabilities=${info2?.rspCapabilities}")
        printWriter.println("TLS anchors usable: " +
            GsmaCi.anchors(info1?.ciForVerification.orEmpty(), roots).size + " of ${roots.size} shipped")
        val notifications = client.retrieveNotifications(euicc, NotificationEvents.ALL).value
            ?.mapNotNull { PendingNotification.parseOrNull(it?.data) }
        val owned = OwnedProfiles.load(this)
        printWriter.println("notifications: " + if (notifications == null) "unreadable" else
            "pending=${notifications.size} " + listOf("install" to NotificationEvents.INSTALL,
                "enable" to NotificationEvents.ENABLE, "disable" to NotificationEvents.DISABLE,
                "delete" to NotificationEvents.DELETE).joinToString(" ") { (name, bit) ->
                "$name=${notifications.count { it.metadata.event == bit }}"
            } + " ours=" + (owned?.let { set -> notifications.count { n -> n.metadata.iccid?.let { it in set } == true } } ?: "locked"))
        printWriter.println("downloaded here: ${owned?.size ?: "locked"}")
    }

    private inline fun withEuicc(slotId: Int, operation: (Euicc) -> Int): Int {
        val euicc = client.euicc(slotId) ?: return Results.EUICC_MISSING
        return operation(euicc)
    }

    private companion object {
        const val TAG = "DiamaneOSEuicc"
    }
}
