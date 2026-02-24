package com.ritam.fishnet

import android.content.Context
import java.util.Calendar
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

data class AdStats(
    val totalAdsDetected: Int = 0,
    val totalAdsBlocked: Int = 0,
    val totalAdsAllowed: Int = 0
) {
    val suppressionEfficiencyPercent: Int
        get() = if (totalAdsDetected <= 0) 0 else ((totalAdsBlocked * 100f) / totalAdsDetected).toInt()
}

object AdStatsManager {
    private const val PREFS = "fishnet_ad_stats_prefs"
    private const val KEY_DETECTED = "total_ads_detected"
    private const val KEY_BLOCKED = "total_ads_blocked"
    private const val KEY_ALLOWED = "total_ads_allowed"
    private const val KEY_LAST_RESET_AT = "last_reset_at"

    private val lock = Mutex()
    private var appContext: Context? = null
    private val state = MutableStateFlow(AdStats())
    val statsFlow: StateFlow<AdStats> = state.asStateFlow()

    suspend fun initialize(context: Context) {
        lock.withLock {
            appContext = context.applicationContext
            maybeResetDailyLocked()
            state.value = readStatsLocked()
        }
    }

    suspend fun recordAdDetected(blocked: Boolean) {
        lock.withLock {
            val prefs = prefsLocked() ?: return
            maybeResetDailyLocked()
            val current = readStatsLocked()
            val next = current.copy(
                totalAdsDetected = current.totalAdsDetected + 1,
                totalAdsBlocked = current.totalAdsBlocked + if (blocked) 1 else 0,
                totalAdsAllowed = current.totalAdsAllowed + if (blocked) 0 else 1
            )
            prefs.edit()
                .putInt(KEY_DETECTED, next.totalAdsDetected)
                .putInt(KEY_BLOCKED, next.totalAdsBlocked)
                .putInt(KEY_ALLOWED, next.totalAdsAllowed)
                .putLong(KEY_LAST_RESET_AT, todayStartMillis())
                .apply()
            state.value = next
        }
    }

    suspend fun getAdStats(): AdStats {
        lock.withLock {
            maybeResetDailyLocked()
            val refreshed = readStatsLocked()
            state.value = refreshed
            return refreshed
        }
    }

    private fun readStatsLocked(): AdStats {
        val prefs = prefsLocked() ?: return state.value
        return AdStats(
            totalAdsDetected = prefs.getInt(KEY_DETECTED, 0),
            totalAdsBlocked = prefs.getInt(KEY_BLOCKED, 0),
            totalAdsAllowed = prefs.getInt(KEY_ALLOWED, 0)
        )
    }

    private fun maybeResetDailyLocked() {
        val prefs = prefsLocked() ?: return
        val todayStart = todayStartMillis()
        val lastReset = prefs.getLong(KEY_LAST_RESET_AT, -1L)

        if (lastReset == todayStart) {
            return
        }

        prefs.edit()
            .putInt(KEY_DETECTED, 0)
            .putInt(KEY_BLOCKED, 0)
            .putInt(KEY_ALLOWED, 0)
            .putLong(KEY_LAST_RESET_AT, todayStart)
            .apply()
    }

    private fun todayStartMillis(): Long {
        val now = Calendar.getInstance()
        now.set(Calendar.HOUR_OF_DAY, 0)
        now.set(Calendar.MINUTE, 0)
        now.set(Calendar.SECOND, 0)
        now.set(Calendar.MILLISECOND, 0)
        return now.timeInMillis
    }

    private fun prefsLocked() = appContext?.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
}
