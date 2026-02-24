package com.ritam.fishnet

import android.content.Context
import android.util.Log
import com.ritam.fishnet.security.db.AppReputation
import com.ritam.fishnet.security.db.AppReputationDao
import com.ritam.fishnet.security.db.FishNetSecurityDatabase
import com.ritam.fishnet.security.db.UserFeedback
import com.ritam.fishnet.security.db.UserFeedbackDao
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

data class FeedbackEvent(
    val notificationId: String,
    val originalClassification: ClassificationType,
    val userClassification: ClassificationType,
    val packageName: String,
    val domain: String?
)

enum class FeedbackSubmitStatus {
    SAVED,
    ALREADY_SUBMITTED,
    ERROR
}

object UserFeedbackRepository {
    private val lock = Mutex()
    private var feedbackDao: UserFeedbackDao? = null
    private var appReputationDao: AppReputationDao? = null
    private var appContext: Context? = null
    private val feedbackEventsState = MutableStateFlow<FeedbackEvent?>(null)
    val feedbackEvents: StateFlow<FeedbackEvent?> = feedbackEventsState.asStateFlow()
    private const val PREFS = "fishnet_feedback_prefs"
    private const val KEY_RISK_ADJUSTMENT_DISABLED_UNTIL = "risk_adjustment_disabled_until"

    suspend fun initialize(context: Context) {
        lock.withLock {
            if (feedbackDao != null && appReputationDao != null) return
            appContext = context.applicationContext
            val db = runCatching {
                FishNetSecurityDatabase.getInstance(context.applicationContext)
            }.onFailure {
                Log.e(TAG, "Failed to initialize feedback DB", it)
            }.getOrNull() ?: return
            feedbackDao = db.userFeedbackDao()
            appReputationDao = db.appReputationDao()
        }
    }

    suspend fun handleUserFeedback(
        notificationId: String,
        originalClassification: ClassificationType,
        userClassification: ClassificationType,
        packageName: String,
        text: String,
        domain: String?
    ): FeedbackSubmitStatus {
        val dao = feedbackDao ?: return FeedbackSubmitStatus.ERROR
        val reputationDao = appReputationDao
        val stableNotificationId = if (notificationId.isBlank()) {
            "$packageName|${text.trim()}".hashCode().toString()
        } else {
            notificationId
        }
        if (dao.getFeedbackByNotificationId(stableNotificationId) != null) {
            return FeedbackSubmitStatus.ALREADY_SUBMITTED
        }
        val now = System.currentTimeMillis()
        return runCatching {
            dao.insertFeedback(
                UserFeedback(
                    notificationId = stableNotificationId,
                    packageName = packageName,
                    domain = domain,
                    originalClassification = originalClassification.name,
                    userClassification = userClassification.name,
                    timestamp = now
                )
            )
            if (reputationDao != null) {
                updateAppReputation(
                    reputationDao = reputationDao,
                    packageName = packageName,
                    userClassification = userClassification
                )
            }
            refreshAntiPoisoningWindow(dao, now)
            applyRealtimeOverride(
                notificationId = stableNotificationId,
                originalClassification = originalClassification,
                userClassification = userClassification
            )
            feedbackEventsState.value = FeedbackEvent(
                notificationId = stableNotificationId,
                originalClassification = originalClassification,
                userClassification = userClassification,
                packageName = packageName,
                domain = domain
            )
            FeedbackSubmitStatus.SAVED
        }.onFailure {
            Log.e(TAG, "Failed to save feedback for notificationId=$stableNotificationId", it)
        }.getOrDefault(FeedbackSubmitStatus.ERROR)
    }

    suspend fun annotateWithFeedback(results: List<ScanResult>): List<ScanResult> {
        val dao = feedbackDao ?: return results
        if (results.isEmpty()) return results
        val ids = results.map { it.notificationId }
        val feedbackMap = dao.getFeedbackByNotificationIds(ids)
            .associateBy { it.notificationId }
        return results.map { item ->
            val feedback = feedbackMap[item.notificationId]?.userClassification
            if (feedback == null) item else item.copy(feedbackClassification = feedback)
        }
    }

    suspend fun feedbackOverride(notificationId: String): ClassificationType? {
        val row = feedbackDao?.getFeedbackByNotificationId(notificationId) ?: return null
        return row.userClassification.toClassificationTypeOrNull()
    }

    suspend fun domainRiskAdjustment(domain: String?): Float {
        if (domain.isNullOrBlank()) return 0f
        if (isRiskAdjustmentBlocked()) return 0f
        val dao = feedbackDao ?: return 0f
        val safeCount = dao.countSafeOverridesForDomain(domain)
        val phishingCount = dao.countPhishingOverridesForDomain(domain)
        return when {
            safeCount >= 3 && phishingCount == 0 -> -0.2f
            phishingCount >= 2 -> 0.25f
            else -> 0f
        }
    }

    suspend fun appRiskAdjustment(packageName: String): Float {
        if (isRiskAdjustmentBlocked()) return 0f
        return appReputationDao?.getByPackage(packageName)?.riskAdjustment ?: 0f
    }

    private suspend fun updateAppReputation(
        reputationDao: AppReputationDao,
        packageName: String,
        userClassification: ClassificationType
    ) {
        val current = reputationDao.getByPackage(packageName) ?: AppReputation(
            packageName = packageName,
            safeOverrides = 0,
            phishingOverrides = 0,
            riskAdjustment = 0f
        )
        val safe = current.safeOverrides + if (userClassification == ClassificationType.SAFE_USEFUL) 1 else 0
        val phishing = current.phishingOverrides + if (userClassification == ClassificationType.PHISHING) 1 else 0
        val adjustment = when {
            safe >= 5 -> -0.15f
            phishing >= 3 -> 0.15f
            else -> current.riskAdjustment
        }
        reputationDao.upsert(
            current.copy(
                safeOverrides = safe,
                phishingOverrides = phishing,
                riskAdjustment = adjustment
            )
        )
    }

    private suspend fun refreshAntiPoisoningWindow(dao: UserFeedbackDao, now: Long) {
        val oneHourAgo = now - 60L * 60L * 1000L
        val count = dao.countPhishingToSafeOverridesSince(oneHourAgo)
        if (count >= 10) {
            val prefs = appContext?.getSharedPreferences(PREFS, Context.MODE_PRIVATE) ?: return
            prefs.edit().putLong(KEY_RISK_ADJUSTMENT_DISABLED_UNTIL, now + 60L * 60L * 1000L).apply()
        }
    }

    private fun isRiskAdjustmentBlocked(): Boolean {
        val prefs = appContext?.getSharedPreferences(PREFS, Context.MODE_PRIVATE) ?: return false
        val until = prefs.getLong(KEY_RISK_ADJUSTMENT_DISABLED_UNTIL, 0L)
        return System.currentTimeMillis() < until
    }

    private suspend fun applyRealtimeOverride(
        notificationId: String,
        originalClassification: ClassificationType,
        userClassification: ClassificationType
    ) {
        val updated = ScanRepository.applyFeedbackOverride(notificationId, userClassification) ?: return
        NotificationStatsRepository.applyFeedbackOverride(
            from = originalClassification,
            to = userClassification
        )
        ScanRepository.refreshThreatPreview(
            packageName = updated.packageName,
            subtype = updated.subtype,
            text = updated.text
        )
    }

    private fun String.toClassificationTypeOrNull(): ClassificationType? {
        return ClassificationType.values().firstOrNull { it.name == this }
    }

    private const val TAG = "UserFeedbackRepository"
}
