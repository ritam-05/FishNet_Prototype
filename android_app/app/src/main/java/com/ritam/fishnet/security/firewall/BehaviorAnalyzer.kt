package com.ritam.fishnet.security.firewall

import com.ritam.fishnet.security.db.AppBehaviorProfile
import com.ritam.fishnet.security.db.AppBehaviorProfileDao
import com.ritam.fishnet.security.db.AppUsageProfile
import com.ritam.fishnet.security.db.AppUsageProfileDao
import kotlin.math.abs

class BehaviorAnalyzer(
    private val behaviorDao: AppBehaviorProfileDao,
    private val usageDao: AppUsageProfileDao
) {
    suspend fun computeAnomalyAndUpdate(
        packageName: String,
        hasUrl: Boolean,
        hasActionVerb: Boolean,
        timestamp: Long
    ): Float {
        val current = behaviorDao.get(packageName)
        if (current == null) {
            behaviorDao.upsert(
                AppBehaviorProfile(
                    packageName = packageName,
                    avgNotificationsPerDay = 1f,
                    avgUrlRate = if (hasUrl) 1f else 0f,
                    avgActionVerbRate = if (hasActionVerb) 1f else 0f,
                    lastSeenTime = timestamp,
                    totalNotifications = 1
                )
            )
            updateUsage(packageName, timestamp)
            return 0f
        }

        val anomaly = calculateAnomaly(
            profile = current,
            hasUrl = hasUrl,
            hasActionVerb = hasActionVerb,
            timestamp = timestamp
        )

        val elapsedMs = (timestamp - current.lastSeenTime).coerceAtLeast(1L)
        val instantPerDay = (86_400_000f / elapsedMs.toFloat()).coerceAtMost(500f)
        val alpha = 0.08f
        val updated = current.copy(
            avgNotificationsPerDay = lerp(current.avgNotificationsPerDay, instantPerDay, alpha),
            avgUrlRate = lerp(current.avgUrlRate, if (hasUrl) 1f else 0f, alpha),
            avgActionVerbRate = lerp(current.avgActionVerbRate, if (hasActionVerb) 1f else 0f, alpha),
            lastSeenTime = timestamp,
            totalNotifications = current.totalNotifications + 1
        )
        behaviorDao.upsert(updated)
        updateUsage(packageName, timestamp)
        return anomaly
    }

    suspend fun shouldAutoHidePromotion(packageName: String, timestamp: Long): Boolean {
        val usage = usageDao.get(packageName) ?: return false
        val thirtyDaysMs = 30L * 24L * 60L * 60L * 1000L
        return (timestamp - usage.lastOpenedTime) >= thirtyDaysMs
    }

    private fun calculateAnomaly(
        profile: AppBehaviorProfile,
        hasUrl: Boolean,
        hasActionVerb: Boolean,
        timestamp: Long
    ): Float {
        val expectedInterval = if (profile.avgNotificationsPerDay <= 0.01f) {
            86_400_000f
        } else {
            86_400_000f / profile.avgNotificationsPerDay
        }
        val actualInterval = (timestamp - profile.lastSeenTime).coerceAtLeast(1L).toFloat()
        val frequencySpike = ((expectedInterval - actualInterval) / expectedInterval).coerceIn(0f, 1f)

        val urlDelta = abs((if (hasUrl) 1f else 0f) - profile.avgUrlRate)
        val actionDelta = abs((if (hasActionVerb) 1f else 0f) - profile.avgActionVerbRate)

        return (0.5f * frequencySpike + 0.25f * urlDelta + 0.25f * actionDelta).coerceIn(0f, 1f)
    }

    private suspend fun updateUsage(packageName: String, timestamp: Long) {
        val current = usageDao.get(packageName)
        val updated = if (current == null) {
            AppUsageProfile(
                packageName = packageName,
                lastOpenedTime = 0L,
                lastNotificationTime = timestamp,
                notificationCount = 1
            )
        } else {
            current.copy(
                lastNotificationTime = timestamp,
                notificationCount = current.notificationCount + 1
            )
        }
        usageDao.upsert(updated)
    }

    private fun lerp(old: Float, new: Float, alpha: Float): Float {
        return old + (new - old) * alpha
    }
}

