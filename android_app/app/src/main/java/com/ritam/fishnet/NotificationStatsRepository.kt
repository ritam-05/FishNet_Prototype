package com.ritam.fishnet

import android.content.Context
import android.util.Log
import com.ritam.fishnet.security.db.FishNetSecurityDatabase
import com.ritam.fishnet.security.db.NotificationStats
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.time.LocalDate
import java.time.format.DateTimeFormatter

enum class NotificationCategory {
    SAFE,
    PHISHING,
    SCAM,
    AD,
    SPAM
}

object NotificationStatsRepository {
    data class StatsState(
        val scannedToday: Int = 0,
        val phishingToday: Int = 0,
        val scamToday: Int = 0,
        val spamToday: Int = 0,
        val adsToday: Int = 0,
        val totalPhishing: Int = 0,
        val totalScam: Int = 0,
        val totalAds: Int = 0,
        val totalSpam: Int = 0,
        val lastResetDate: String = currentDateString()
    )

    private val lock = Mutex()
    private var dao: com.ritam.fishnet.security.db.NotificationStatsDao? = null
    private val flowState = kotlinx.coroutines.flow.MutableStateFlow(StatsState())
    val statsFlow: kotlinx.coroutines.flow.StateFlow<StatsState> = flowState

    suspend fun initialize(context: Context) {
        lock.withLock {
            if (dao == null) {
                dao = runCatching {
                    FishNetSecurityDatabase.getInstance(context.applicationContext).notificationStatsDao()
                }.onFailure {
                    Log.e(TAG, "Room unavailable for stats. Using in-memory stats only.", it)
                }.getOrNull()
            }
            val current = dao?.get()
            val initial = current ?: NotificationStats(
                id = 1,
                scannedToday = flowState.value.scannedToday,
                phishingToday = flowState.value.phishingToday,
                scamToday = flowState.value.scamToday,
                spamToday = flowState.value.spamToday,
                adsToday = flowState.value.adsToday,
                totalPhishing = flowState.value.totalPhishing,
                totalScam = flowState.value.totalScam,
                totalAds = flowState.value.totalAds,
                totalSpam = flowState.value.totalSpam,
                lastResetDate = currentDateString()
            )
            dao?.upsert(initial)
            flowState.value = maybeReset(initial).toState()
        }
    }

    suspend fun recordProcessed(category: NotificationCategory) {
        lock.withLock {
            val store = dao
            val currentFallback = NotificationStats(
                id = 1,
                scannedToday = flowState.value.scannedToday,
                phishingToday = flowState.value.phishingToday,
                scamToday = flowState.value.scamToday,
                spamToday = flowState.value.spamToday,
                adsToday = flowState.value.adsToday,
                totalPhishing = flowState.value.totalPhishing,
                totalScam = flowState.value.totalScam,
                totalAds = flowState.value.totalAds,
                totalSpam = flowState.value.totalSpam,
                lastResetDate = flowState.value.lastResetDate
            )
            val base = maybeReset(
                store?.get() ?: currentFallback
            )
            val next = when (category) {
                NotificationCategory.PHISHING -> base.copy(
                    scannedToday = base.scannedToday + 1,
                    phishingToday = base.phishingToday + 1,
                    totalPhishing = base.totalPhishing + 1
                )
                NotificationCategory.SCAM -> base.copy(
                    scannedToday = base.scannedToday + 1,
                    scamToday = base.scamToday + 1,
                    totalScam = base.totalScam + 1
                )
                NotificationCategory.AD -> base.copy(
                    scannedToday = base.scannedToday + 1,
                    adsToday = base.adsToday + 1,
                    totalAds = base.totalAds + 1
                )
                NotificationCategory.SPAM -> base.copy(
                    scannedToday = base.scannedToday + 1,
                    spamToday = base.spamToday + 1,
                    totalSpam = base.totalSpam + 1
                )
                NotificationCategory.SAFE -> base.copy(
                    scannedToday = base.scannedToday + 1
                )
            }
            store?.upsert(next)
            flowState.value = next.toState()
        }
    }

    suspend fun applyFeedbackOverride(from: ClassificationType, to: ClassificationType) {
        if (from == to) return
        lock.withLock {
            val store = dao
            val currentFallback = NotificationStats(
                id = 1,
                scannedToday = flowState.value.scannedToday,
                phishingToday = flowState.value.phishingToday,
                scamToday = flowState.value.scamToday,
                spamToday = flowState.value.spamToday,
                adsToday = flowState.value.adsToday,
                totalPhishing = flowState.value.totalPhishing,
                totalScam = flowState.value.totalScam,
                totalAds = flowState.value.totalAds,
                totalSpam = flowState.value.totalSpam,
                lastResetDate = flowState.value.lastResetDate
            )
            var base = maybeReset(store?.get() ?: currentFallback)
            base = decrementFor(base, from)
            base = incrementFor(base, to)
            store?.upsert(base)
            flowState.value = base.toState()
        }
    }

    private fun decrementFor(base: NotificationStats, classification: ClassificationType): NotificationStats {
        return when (classification) {
            ClassificationType.PHISHING -> base.copy(
                phishingToday = (base.phishingToday - 1).coerceAtLeast(0),
                totalPhishing = (base.totalPhishing - 1).coerceAtLeast(0)
            )
            ClassificationType.SCAM -> base.copy(
                scamToday = (base.scamToday - 1).coerceAtLeast(0),
                totalScam = (base.totalScam - 1).coerceAtLeast(0)
            )
            ClassificationType.IRRELEVANT_AD -> base.copy(
                adsToday = (base.adsToday - 1).coerceAtLeast(0),
                totalAds = (base.totalAds - 1).coerceAtLeast(0)
            )
            ClassificationType.SPAM -> base.copy(
                spamToday = (base.spamToday - 1).coerceAtLeast(0),
                totalSpam = (base.totalSpam - 1).coerceAtLeast(0)
            )
            ClassificationType.SAFE_USEFUL -> base
        }
    }

    private fun incrementFor(base: NotificationStats, classification: ClassificationType): NotificationStats {
        return when (classification) {
            ClassificationType.PHISHING -> base.copy(
                phishingToday = base.phishingToday + 1,
                totalPhishing = base.totalPhishing + 1
            )
            ClassificationType.SCAM -> base.copy(
                scamToday = base.scamToday + 1,
                totalScam = base.totalScam + 1
            )
            ClassificationType.IRRELEVANT_AD -> base.copy(
                adsToday = base.adsToday + 1,
                totalAds = base.totalAds + 1
            )
            ClassificationType.SPAM -> base.copy(
                spamToday = base.spamToday + 1,
                totalSpam = base.totalSpam + 1
            )
            ClassificationType.SAFE_USEFUL -> base
        }
    }

    private fun maybeReset(stats: NotificationStats): NotificationStats {
        val today = currentDateString()
        if (stats.lastResetDate == today) return stats
        return stats.copy(
            scannedToday = 0,
            phishingToday = 0,
            scamToday = 0,
            spamToday = 0,
            adsToday = 0,
            lastResetDate = today
        )
    }

    private fun NotificationStats.toState(): StatsState {
        return StatsState(
            scannedToday = scannedToday,
            phishingToday = phishingToday,
            scamToday = scamToday,
            spamToday = spamToday,
            adsToday = adsToday,
            totalPhishing = totalPhishing,
            totalScam = totalScam,
            totalAds = totalAds,
            totalSpam = totalSpam,
            lastResetDate = lastResetDate
        )
    }

    private fun currentDateString(): String {
        return LocalDate.now().format(DateTimeFormatter.ISO_LOCAL_DATE)
    }

    private const val TAG = "NotificationStatsRepo"
}
