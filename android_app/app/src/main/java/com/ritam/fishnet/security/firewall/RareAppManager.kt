package com.ritam.fishnet.security.firewall

import android.content.Context
import com.ritam.fishnet.AppSettings
import com.ritam.fishnet.security.db.AppUsageStats
import com.ritam.fishnet.security.db.AppUsageStatsDao
import java.time.LocalDate
import java.time.YearMonth
import java.util.concurrent.ConcurrentHashMap

data class RareAppState(
    val isLowPriority: Boolean,
    val openCountMonth: Int,
    val notificationCountToday: Int
)

class RareAppManager(
    private val appContext: Context,
    private val appUsageStatsDao: AppUsageStatsDao
) {
    private val labelCounters = ConcurrentHashMap<String, Pair<Int, Int>>()
    private val prefs = appContext.getSharedPreferences("rare_app_manager_prefs", Context.MODE_PRIVATE)

    suspend fun prepareWindowResetsIfNeeded() {
        val today = LocalDate.now().toString()
        val month = YearMonth.now().toString()
        if (prefs.getString(KEY_LAST_DAY_RESET, null) != today) {
            appUsageStatsDao.resetDailyNotificationCounts()
            labelCounters.clear()
            prefs.edit().putString(KEY_LAST_DAY_RESET, today).apply()
        }
        if (prefs.getString(KEY_LAST_MONTH_RESET, null) != month) {
            appUsageStatsDao.resetMonthlyOpenCounts()
            prefs.edit().putString(KEY_LAST_MONTH_RESET, month).apply()
        }
    }

    suspend fun recordNotification(packageName: String): RareAppState {
        prepareWindowResetsIfNeeded()
        val current = appUsageStatsDao.get(packageName)
        val updated = if (current == null) {
            AppUsageStats(
                packageName = packageName,
                openCountMonth = 0,
                notificationCountToday = 1,
                lastOpened = 0L,
                isLowPriority = false
            )
        } else {
            current.copy(notificationCountToday = current.notificationCountToday + 1)
        }
        appUsageStatsDao.upsert(updated)
        return RareAppState(
            isLowPriority = updated.isLowPriority,
            openCountMonth = updated.openCountMonth,
            notificationCountToday = updated.notificationCountToday
        )
    }

    suspend fun recordLikelyOpen(packageName: String, timestamp: Long) {
        val current = appUsageStatsDao.get(packageName)
        val updated = if (current == null) {
            AppUsageStats(
                packageName = packageName,
                openCountMonth = 1,
                notificationCountToday = 0,
                lastOpened = timestamp,
                isLowPriority = false
            )
        } else {
            current.copy(
                openCountMonth = current.openCountMonth + 1,
                lastOpened = timestamp,
                isLowPriority = false
            )
        }
        appUsageStatsDao.upsert(updated)
    }

    suspend fun evaluateSuppression(packageName: String, label: SecurityLabel): Boolean {
        if (!AppSettings.isLowPrioritySuppressionEnabled(appContext)) return false

        val stats = appUsageStatsDao.get(packageName) ?: return false
        val counter = labelCounters[packageName] ?: (0 to 0)
        val total = counter.first + 1
        val irrelevantLikeCount = counter.second + if (
            label == SecurityLabel.IRRELEVANT_AD || label == SecurityLabel.SPAM
        ) {
            1
        } else {
            0
        }
        labelCounters[packageName] = total to irrelevantLikeCount

        val mostlyIrrelevant = total >= 6 && (irrelevantLikeCount.toFloat() / total.toFloat()) >= 0.70f
        val frequentNotifications = stats.notificationCountToday >= 6
        val rarelyOpened = stats.openCountMonth < 2
        val shouldLowPriority = rarelyOpened && frequentNotifications && mostlyIrrelevant

        if (shouldLowPriority != stats.isLowPriority) {
            appUsageStatsDao.upsert(stats.copy(isLowPriority = shouldLowPriority))
        }
        return shouldLowPriority || stats.isLowPriority
    }

    companion object {
        private const val KEY_LAST_DAY_RESET = "last_day_reset"
        private const val KEY_LAST_MONTH_RESET = "last_month_reset"
    }
}
