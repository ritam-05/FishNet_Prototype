package com.ritam.fishnet

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.ContactsContract
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Log
import androidx.core.content.ContextCompat
import androidx.core.app.NotificationCompat
import com.ritam.fishnet.security.firewall.NotificationProcessor
import com.ritam.fishnet.security.firewall.SecurityLabel
import com.ritam.fishnet.security.firewall.SecurityDecision
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

class NotificationService : NotificationListenerService() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private lateinit var notificationProcessor: NotificationProcessor

    override fun onCreate() {
        super.onCreate()
        notificationProcessor = NotificationProcessor.getInstance(applicationContext)
        createNotificationChannels()
        serviceScope.launch {
            NotificationStatsRepository.initialize(applicationContext)
            UserFeedbackRepository.initialize(applicationContext)
            AdStatsManager.initialize(applicationContext)
            PerAppAdControlManager.initialize(applicationContext)
            AdBlockHistoryManager.initialize(applicationContext)
        }
    }

    override fun onDestroy() {
        serviceScope.cancel()
        super.onDestroy()
    }

    override fun onListenerConnected() {
        super.onListenerConnected()
        triggerExistingNotificationScan("listener_connected")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_SCAN_EXISTING_NOTIFICATIONS) {
            triggerExistingNotificationScan("app_launch")
        }
        return START_STICKY
    }

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        if (!AppSettings.isProtectionEnabled(applicationContext)) return
        val notification = sbn ?: return
        serviceScope.launch {
            processNotification(notification, source = "realtime")
        }
    }

    private fun triggerExistingNotificationScan(trigger: String) {
        if (!AppSettings.isProtectionEnabled(applicationContext)) return
        serviceScope.launch {
            val active = try {
                activeNotifications ?: emptyArray()
            } catch (e: Exception) {
                Log.e(TAG, "Failed to access active notifications for trigger=$trigger", e)
                emptyArray()
            }

            var phishing = 0
            var scam = 0
            var irrelevant = 0
            active.forEach { sbn ->
                when (processNotification(sbn, source = "startup:$trigger")) {
                    ProcessOutcome.USEFUL -> Unit
                    ProcessOutcome.PHISHING -> phishing += 1
                    ProcessOutcome.SCAM -> scam += 1
                    ProcessOutcome.IRRELEVANT -> irrelevant += 1
                    ProcessOutcome.SKIPPED -> Unit
                }
            }
            val useful = (active.size - phishing - scam - irrelevant).coerceAtLeast(0)
            postStartupSummary(
                requestedCount = active.size,
                useful = useful,
                phishing = phishing,
                scam = scam,
                irrelevant = irrelevant,
                skipped = 0,
                trigger = trigger
            )
        }
    }

    private suspend fun processNotification(sbn: StatusBarNotification, source: String): ProcessOutcome {
        if (!AppSettings.isProtectionEnabled(applicationContext)) return ProcessOutcome.SKIPPED
        if (sbn.packageName == packageName) return ProcessOutcome.SKIPPED
        if (isMusicPlaybackNotification(sbn.notification)) return ProcessOutcome.SKIPPED

        val notificationKey = buildNotificationKey(sbn)
        val isStartupScan = source.startsWith("startup:")
        val alreadyProcessed = !ScanRepository.markProcessed(notificationKey)
        if (alreadyProcessed && !isStartupScan) {
            Log.d(TAG, "Skipping duplicate notification key=$notificationKey source=$source")
            return ProcessOutcome.SKIPPED
        }

        val text = extractNotificationText(sbn.notification)
        val timestamp = System.currentTimeMillis()
        val decision = notificationProcessor.processNotification(
            notificationId = notificationKey,
            text = text,
            packageName = sbn.packageName,
            timestamp = timestamp
        )
        var normalizedDecision = normalizeWhatsAppDecision(
            packageName = sbn.packageName,
            notification = sbn.notification,
            text = text,
            decision = decision
        )
        normalizedDecision = normalizeShoppingPromoDecision(
            packageName = sbn.packageName,
            text = text,
            decision = normalizedDecision
        )
        normalizedDecision = normalizeGeneralPromoDecision(
            packageName = sbn.packageName,
            text = text,
            decision = normalizedDecision
        )
        val aggressiveEnabled = AppSettings.isAggressiveEnabled(applicationContext)

        val aggressiveNonAdBlock =
            aggressiveEnabled &&
                shouldAggressiveBlock(normalizedDecision.label, sbn.packageName) &&
                normalizedDecision.label != SecurityLabel.IRRELEVANT_AD
        if (normalizedDecision.shouldBlock || aggressiveNonAdBlock) {
            sbn.key?.let { cancelNotification(it) }
        }

        if (isPhishingLabel(normalizedDecision.label)) {
            if (alreadyProcessed) return ProcessOutcome.SKIPPED
            val phishingSubtype = normalizedDecision.threatSubtype ?: "General Phishing"
            ScanRepository.recordPhishingDetection(
                notificationId = notificationKey,
                packageName = sbn.packageName,
                text = text,
                timestamp = timestamp,
                phishingSubtype = phishingSubtype
            )
            NotificationStatsRepository.recordProcessed(NotificationCategory.PHISHING)
            if (normalizedDecision.finalRisk >= PHISHING_ALERT_MIN_RISK) {
                showPhishingAlert(
                    notificationId = buildAlertId(sbn, source, text),
                    packageName = sbn.packageName,
                    confidence = normalizedDecision.finalRisk,
                    text = text,
                    phishingSubtype = phishingSubtype,
                    confidenceLevel = normalizedDecision.riskMeter.name,
                    promptProtectedMode = normalizedDecision.promptProtectedMode
                )
            }
            return ProcessOutcome.PHISHING
        }

        if (normalizedDecision.label == SecurityLabel.SCAM) {
            if (alreadyProcessed) return ProcessOutcome.SKIPPED
            val scamSubtype = normalizedDecision.threatSubtype ?: "SCAM_GENERAL"
            ScanRepository.recordScamDetection(
                notificationId = notificationKey,
                packageName = sbn.packageName,
                text = text,
                timestamp = timestamp,
                scamSubtype = scamSubtype
            )
            NotificationStatsRepository.recordProcessed(NotificationCategory.SCAM)
            showScamAlert(
                notificationId = buildAlertId(sbn, source, "scam|$text"),
                packageName = sbn.packageName,
                confidence = normalizedDecision.finalRisk,
                text = text,
                scamSubtype = scamSubtype,
                confidenceLevel = normalizedDecision.riskMeter.name
            )
            return ProcessOutcome.SCAM
        }

        ScanRepository.recordScan(timestamp)
        val category = when (normalizedDecision.label) {
            SecurityLabel.IRRELEVANT_AD -> ScanCategory.IRRELEVANT.name
            SecurityLabel.SPAM -> ScanCategory.IRRELEVANT.name
            SecurityLabel.SCAM -> ScanCategory.SCAM.name
            else -> ScanCategory.USEFUL.name
        }
        val subtype = when {
            normalizedDecision.label == SecurityLabel.SPAM -> "Spam"
            normalizedDecision.lowPriorityBucket -> "Low Priority Promotion"
            else -> null
        }
        var adWasBlocked = false
        if (normalizedDecision.label == SecurityLabel.IRRELEVANT_AD) {
            adWasBlocked = shouldBlockAdvertisement(
                packageName = sbn.packageName,
                text = text,
                notification = sbn.notification,
                aggressiveEnabled = aggressiveEnabled
            )
            AdStatsManager.recordAdDetected(blocked = adWasBlocked)
            if (adWasBlocked) {
                AdBlockHistoryManager.recordBlockedAd(
                    packageName = sbn.packageName,
                    text = text,
                    timestamp = timestamp,
                    context = applicationContext,
                    sourceType = if (isWhatsAppPackage(sbn.packageName)) {
                        AdBlockHistoryManager.SOURCE_WHATSAPP_UNKNOWN_AD
                    } else {
                        "general_ad"
                    }
                )
                sbn.key?.let { cancelNotification(it) }
            }
            if (alreadyProcessed) {
                return ProcessOutcome.IRRELEVANT
            }
        }

        if (alreadyProcessed) return ProcessOutcome.SKIPPED

        if (!normalizedDecision.lowPriorityBucket && !adWasBlocked) {
            ScanRepository.addResult(
                ScanResult(
                    notificationId = notificationKey,
                    packageName = sbn.packageName,
                    text = text,
                    category = category,
                    subtype = subtype,
                    timestamp = timestamp,
                    feedbackClassification = null
                )
            )
        }
        when (normalizedDecision.label) {
            SecurityLabel.IRRELEVANT_AD -> NotificationStatsRepository.recordProcessed(NotificationCategory.AD)
            SecurityLabel.SPAM -> NotificationStatsRepository.recordProcessed(NotificationCategory.SPAM)
            SecurityLabel.SCAM -> NotificationStatsRepository.recordProcessed(NotificationCategory.SCAM)
            else -> NotificationStatsRepository.recordProcessed(NotificationCategory.SAFE)
        }
        return if (normalizedDecision.label == SecurityLabel.IRRELEVANT_AD || normalizedDecision.label == SecurityLabel.SPAM) {
            ProcessOutcome.IRRELEVANT
        } else {
            ProcessOutcome.USEFUL
        }
    }

    private fun postStartupSummary(
        requestedCount: Int,
        useful: Int,
        phishing: Int,
        scam: Int,
        irrelevant: Int,
        skipped: Int,
        trigger: String
    ) {
        val line = "Scanned $requestedCount notifications: $useful useful, " +
            "$phishing phishing, $scam scam, $irrelevant irrelevant"

        val detail = buildString {
            append("Startup scan complete (")
            append(trigger)
            append(").\n")
            append(line)
        }

        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val pending = createOpenAppPendingIntent(
            requestCode = STARTUP_SUMMARY_NOTIFICATION_ID,
            source = "startup_summary"
        )
        val summaryNotification = NotificationCompat.Builder(this, SUMMARY_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setContentTitle("FishNet Scan Summary")
            .setContentText(line)
            .setStyle(NotificationCompat.BigTextStyle().bigText(detail))
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setContentIntent(pending)
            .setAutoCancel(true)
            .build()

        manager.notify(STARTUP_SUMMARY_NOTIFICATION_ID, summaryNotification)
    }

    private fun showPhishingAlert(
        notificationId: Int,
        packageName: String,
        confidence: Float,
        text: String,
        phishingSubtype: String,
        confidenceLevel: String,
        promptProtectedMode: Boolean
    ) {
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val pending = createOpenAppPendingIntent(
            requestCode = notificationId,
            source = "phishing_alert",
            packageName = packageName,
            promptProtectedMode = promptProtectedMode
        )
        val body = buildString {
            append("Phishing detected: ")
            append(phishingSubtype)
            append("\nRisk ${(confidence * 100).toInt()}% ($confidenceLevel)")
            if (promptProtectedMode) {
                append("\nOpen link in protected mode?")
            }
            append("\n\n")
            append(text)
        }
        val alert = NotificationCompat.Builder(this, ALERT_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_notify_error)
            .setContentTitle("FishNet Phishing Alert")
            .setContentText("Phishing detected from $packageName")
            .setStyle(
                NotificationCompat.BigTextStyle().bigText(body)
            )
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setContentIntent(pending)
            .setAutoCancel(true)
            .build()
        manager.notify(notificationId, alert)
    }

    private fun showScamAlert(
        notificationId: Int,
        packageName: String,
        confidence: Float,
        text: String,
        scamSubtype: String,
        confidenceLevel: String
    ) {
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val pending = createOpenAppPendingIntent(
            requestCode = notificationId,
            source = "scam_alert",
            packageName = packageName
        )
        val body = buildString {
            append("Scam job detected: ")
            append(scamSubtype)
            append("\nRisk ${(confidence * 100).toInt()}% ($confidenceLevel)")
            append("\n\n")
            append(text)
        }
        val alert = NotificationCompat.Builder(this, ALERT_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_notify_error)
            .setContentTitle("FishNet Scam Alert")
            .setContentText("Scam job detected from $packageName")
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setContentIntent(pending)
            .setAutoCancel(true)
            .build()
        manager.notify(notificationId, alert)
    }

    private fun createOpenAppPendingIntent(
        requestCode: Int,
        source: String,
        packageName: String? = null,
        promptProtectedMode: Boolean = false
    ): PendingIntent {
        val openAppIntent = Intent(this, MainActivity::class.java).apply {
            action = ACTION_OPEN_FROM_NOTIFICATION
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra(EXTRA_OPEN_SOURCE, source)
            if (!packageName.isNullOrBlank()) {
                putExtra(EXTRA_SOURCE_PACKAGE, packageName)
            }
            putExtra(EXTRA_PROMPT_PROTECTED_MODE, promptProtectedMode)
        }
        return PendingIntent.getActivity(
            this,
            requestCode,
            openAppIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
    }

    private fun createNotificationChannels() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return

        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        val alertChannel = NotificationChannel(
            ALERT_CHANNEL_ID,
            "FishNet Alerts",
            NotificationManager.IMPORTANCE_HIGH
        ).apply {
            description = "High priority alerts for phishing detections"
        }

        val summaryChannel = NotificationChannel(
            SUMMARY_CHANNEL_ID,
            "FishNet Scan Summary",
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "Low priority summaries for startup notification scans"
        }

        manager.createNotificationChannel(alertChannel)
        manager.createNotificationChannel(summaryChannel)
    }

    private fun extractNotificationText(notification: Notification): String {
        val extras = notification.extras ?: return ""
        val title = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString().orEmpty()
        val text = extras.getCharSequence(Notification.EXTRA_TEXT)?.toString().orEmpty()
        val bigText = extras.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString().orEmpty()
        val subText = extras.getCharSequence(Notification.EXTRA_SUB_TEXT)?.toString().orEmpty()

        return listOf(title, text, bigText, subText)
            .filter { it.isNotBlank() }
            .joinToString(separator = " ")
            .trim()
    }

    private fun isMusicPlaybackNotification(notification: Notification): Boolean {
        val isTransportCategory = notification.category == Notification.CATEGORY_TRANSPORT
        val isOngoing = (notification.flags and Notification.FLAG_ONGOING_EVENT) != 0
        val hasPlaybackControls = !notification.actions.isNullOrEmpty()
        return isTransportCategory && isOngoing && hasPlaybackControls
    }

    private fun buildNotificationKey(sbn: StatusBarNotification): String {
        val keyPart = sbn.key ?: "${sbn.packageName}:${sbn.id}:${sbn.postTime}"
        return "$keyPart|${sbn.packageName}"
    }

    private fun buildAlertId(sbn: StatusBarNotification, source: String, text: String): Int {
        return "${sbn.packageName}|${sbn.id}|${sbn.postTime}|$source|$text".hashCode()
    }

    private fun isPhishingLabel(label: SecurityLabel): Boolean {
        return label == SecurityLabel.PHISHING
    }

    private fun shouldAggressiveBlock(label: SecurityLabel, packageName: String): Boolean {
        if (isWhatsAppPackage(packageName)) {
            return false
        }
        if (isSocialMediaPackage(packageName)) {
            return false
        }
        return label == SecurityLabel.IRRELEVANT_AD ||
            label == SecurityLabel.SCAM ||
            label == SecurityLabel.SPAM ||
            label == SecurityLabel.PHISHING
    }

    private suspend fun shouldBlockAdvertisement(
        packageName: String,
        text: String,
        notification: Notification,
        aggressiveEnabled: Boolean
    ): Boolean {
        if (isForceBlockedPromoPackage(packageName)) return true
        if (isWhatsAppPackage(packageName)) {
            return isUnknownWhatsAppSender(notification = notification, fallbackText = text)
        }
        if (isSocialMediaPackage(packageName)) {
            return false
        }
        if (aggressiveEnabled) return true
        val globalAdBlockEnabled = AppSettings.isGlobalAdBlockEnabled(applicationContext)
        return PerAppAdControlManager.shouldBlockAd(
            packageName = packageName,
            globalAdBlockEnabled = globalAdBlockEnabled
        )
    }

    private fun isForceBlockedPromoPackage(packageName: String): Boolean {
        val normalized = packageName.lowercase()
        return normalized == "com.flipkart.android" ||
            normalized == "com.amazon.mshop.android.shopping" ||
            normalized == "in.amazon.mshop.android.shopping"
    }

    private fun isWhatsAppPackage(packageName: String): Boolean {
        val normalized = packageName.lowercase()
        return normalized == "com.whatsapp" || normalized == "com.whatsapp.w4b"
    }

    private fun isSocialMediaPackage(packageName: String): Boolean {
        val normalized = packageName.lowercase()
        if (isWhatsAppPackage(normalized)) return true
        return normalized == "com.instagram.android" ||
            normalized == "com.twitter.android" ||
            normalized == "com.facebook.katana" ||
            normalized == "com.facebook.orca" ||
            normalized == "org.telegram.messenger" ||
            normalized == "org.thunderdog.challegram" ||
            normalized == "com.snapchat.android" ||
            normalized == "com.discord" ||
            normalized == "com.reddit.frontpage" ||
            normalized == "com.linkedin.android"
    }

    private fun normalizeWhatsAppDecision(
        packageName: String,
        notification: Notification,
        text: String,
        decision: SecurityDecision
    ): SecurityDecision {
        if (!isWhatsAppPackage(packageName)) return decision

        val unknownSender = isUnknownWhatsAppSender(notification = notification, fallbackText = text)
        val adFromUnknown = unknownSender && hasWhatsAppAdKeywords(text)
        if (adFromUnknown) {
            return decision.copy(
                label = SecurityLabel.IRRELEVANT_AD,
                threatSubtype = "WhatsApp Unknown Ad",
                shouldBlock = true,
                promptProtectedMode = false,
                lowPriorityBucket = false
            )
        }

        return decision.copy(
            label = SecurityLabel.SAFE_USEFUL,
            threatSubtype = null,
            shouldBlock = false,
            promptProtectedMode = false,
            lowPriorityBucket = false
        )
    }

    private fun normalizeShoppingPromoDecision(
        packageName: String,
        text: String,
        decision: SecurityDecision
    ): SecurityDecision {
        val normalizedPackage = packageName.lowercase()
        val strictPromoPackages = setOf(
            "com.flipkart.android",
            "com.amazon.mshop.android.shopping",
            "in.amazon.mshop.android.shopping"
        )
        val shoppingPackages = setOf(
            "com.flipkart.android",
            "com.amazon.mshop.android.shopping",
            "in.amazon.mshop.android.shopping",
            "com.myntra.android",
            "com.meesho.supply",
            "com.snapdeal.main",
            "com.ril.ajio",
            "com.tatacliq",
            "com.nykaa"
        )
        val isShoppingApp = shoppingPackages.any { normalizedPackage == it || normalizedPackage.startsWith("$it.") }
        if (!isShoppingApp) return decision
        if (decision.label == SecurityLabel.PHISHING || decision.label == SecurityLabel.SCAM) return decision

        val normalizedText = text.lowercase()
        val transactionalKeywords = listOf(
            "order placed", "order confirmed", "order packed", "shipped", "out for delivery",
            "delivered", "delivery by", "return pickup", "refund", "invoice", "cod", "payment received"
        )
        val promoKeywords = listOf(
            "sale", "offer", "discount", "cashback", "coupon", "deal", "limited time",
            "today only", "shop now", "buy now", "wishlist", "price drop", "festival"
        )
        val isTransactional = transactionalKeywords.any { normalizedText.contains(it) }
        val looksPromotional = promoKeywords.any { normalizedText.contains(it) }

        if (isTransactional) return decision
        if (strictPromoPackages.any { normalizedPackage == it || normalizedPackage.startsWith("$it.") }) {
            return decision.copy(
                label = SecurityLabel.IRRELEVANT_AD,
                threatSubtype = "Shopping Promotion",
                shouldBlock = true,
                promptProtectedMode = false,
                lowPriorityBucket = false
            )
        }
        if (!looksPromotional && decision.label != SecurityLabel.IRRELEVANT_AD) return decision

        return decision.copy(
            label = SecurityLabel.IRRELEVANT_AD,
            threatSubtype = "Shopping Promotion",
            shouldBlock = true,
            promptProtectedMode = false,
            lowPriorityBucket = false
        )
    }

    private fun normalizeGeneralPromoDecision(
        packageName: String,
        text: String,
        decision: SecurityDecision
    ): SecurityDecision {
        if (isSocialMediaPackage(packageName)) return decision
        if (isWhatsAppPackage(packageName)) return decision
        if (decision.label == SecurityLabel.PHISHING || decision.label == SecurityLabel.SCAM) return decision

        val normalizedText = text.lowercase()
        val transactionalKeywords = listOf(
            "order placed", "order confirmed", "order packed", "shipped", "out for delivery",
            "delivered", "delivery by", "return pickup", "refund", "invoice", "payment received",
            "otp", "verification code", "security alert", "account login", "transaction"
        )
        val promoKeywords = listOf(
            "sale", "offer", "discount", "cashback", "coupon", "deal", "limited time",
            "today only", "shop now", "buy now", "wishlist", "price drop", "festival",
            "promo", "promotional", "special price", "bonus", "reward", "new arrivals",
            "recommended for you", "subscribe now", "upgrade now", "try premium", "ad-free"
        )

        val isTransactional = transactionalKeywords.any { normalizedText.contains(it) }
        val isPromotional = promoKeywords.any { normalizedText.contains(it) }
        if (!isPromotional || isTransactional) return decision

        return decision.copy(
            label = SecurityLabel.IRRELEVANT_AD,
            threatSubtype = "Promotional Notification",
            shouldBlock = true,
            promptProtectedMode = false,
            lowPriorityBucket = false
        )
    }

    private fun hasWhatsAppAdKeywords(text: String): Boolean {
        val normalized = text.lowercase()
        val keywords = listOf(
            "offer", "discount", "sale", "deal", "limited time", "shop now", "buy now", "order now",
            "coupon", "promo", "cashback", "free delivery", "special price", "price drop", "flat off",
            "join now", "register now", "subscription", "subscribe", "premium", "referral", "earn now"
        )
        return keywords.any { normalized.contains(it) }
    }

    private fun isUnknownWhatsAppSender(notification: Notification, fallbackText: String): Boolean {
        if (ContextCompat.checkSelfPermission(
                applicationContext,
                Manifest.permission.READ_CONTACTS
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            return false
        }

        val senderCandidate = extractPhoneCandidate(notification, fallbackText) ?: return false
        return !isKnownContact(senderCandidate)
    }

    private fun extractPhoneCandidate(notification: Notification, fallbackText: String): String? {
        val extras = notification.extras
        val title = extras?.getCharSequence(Notification.EXTRA_TITLE)?.toString().orEmpty()
        val text = extras?.getCharSequence(Notification.EXTRA_TEXT)?.toString().orEmpty()
        val subText = extras?.getCharSequence(Notification.EXTRA_SUB_TEXT)?.toString().orEmpty()

        val raw = listOf(title, text, subText, fallbackText)
            .joinToString(" ")
            .trim()
        if (raw.isBlank()) return null

        val match = Regex("""(?:\+?\d[\d\s\-\(\)]{7,}\d)""").find(raw)?.value ?: return null
        val digits = match.filter { it.isDigit() }
        if (digits.length < 8) return null
        return if (digits.length > 10) digits.takeLast(10) else digits
    }

    private fun isKnownContact(number: String): Boolean {
        val contentResolver = applicationContext.contentResolver
        val candidates = buildSet {
            add(number)
            if (number.length >= 10) {
                add(number.takeLast(10))
            }
        }
        return candidates.any { candidate ->
            val uri = Uri.withAppendedPath(
                ContactsContract.PhoneLookup.CONTENT_FILTER_URI,
                Uri.encode(candidate)
            )
            runCatching {
                contentResolver.query(
                    uri,
                    arrayOf(ContactsContract.PhoneLookup._ID),
                    null,
                    null,
                    null
                )?.use { cursor ->
                    cursor.moveToFirst()
                } ?: false
            }.getOrDefault(false)
        }
    }

    private fun phishingSubtype(label: SecurityLabel): String {
        return when (label) {
            SecurityLabel.PHISHING -> "General Phishing"
            else -> "General Phishing"
        }
    }

    private enum class ProcessOutcome {
        USEFUL,
        PHISHING,
        SCAM,
        IRRELEVANT,
        SKIPPED
    }

    companion object {
        private const val TAG = "NotificationService"
        const val ACTION_SCAN_EXISTING_NOTIFICATIONS =
            "com.ritam.fishnet.action.SCAN_EXISTING_NOTIFICATIONS"
        const val ACTION_OPEN_FROM_NOTIFICATION =
            "com.ritam.fishnet.action.OPEN_FROM_NOTIFICATION"
        const val EXTRA_OPEN_SOURCE = "extra_open_source"
        const val EXTRA_SOURCE_PACKAGE = "extra_source_package"
        const val EXTRA_PROMPT_PROTECTED_MODE = "extra_prompt_protected_mode"

        private const val ALERT_CHANNEL_ID = "fishnet_alerts"
        private const val SUMMARY_CHANNEL_ID = "fishnet_scan_summary"
        private const val STARTUP_SUMMARY_NOTIFICATION_ID = 70_001
        private const val PHISHING_ALERT_MIN_RISK = 0.60f
    }
}
