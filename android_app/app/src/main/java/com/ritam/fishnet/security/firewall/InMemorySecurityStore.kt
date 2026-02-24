package com.ritam.fishnet.security.firewall

import com.ritam.fishnet.security.db.AppBehaviorProfile
import com.ritam.fishnet.security.db.AppBehaviorProfileDao
import com.ritam.fishnet.security.db.AppUsageProfile
import com.ritam.fishnet.security.db.AppUsageProfileDao
import com.ritam.fishnet.security.db.AppUsageStats
import com.ritam.fishnet.security.db.AppUsageStatsDao
import com.ritam.fishnet.security.db.AppReputation
import com.ritam.fishnet.security.db.AppReputationDao
import com.ritam.fishnet.security.db.DomainProfile
import com.ritam.fishnet.security.db.DomainProfileDao
import com.ritam.fishnet.security.db.UserFeedback
import com.ritam.fishnet.security.db.UserFeedbackDao
import com.ritam.fishnet.security.db.UserOverride
import com.ritam.fishnet.security.db.UserOverrideDao

/**
 * Runtime fallback store used when Room codegen is unavailable.
 * Keeps the firewall functional and prevents service crash loops.
 */
class InMemorySecurityStore {
    val domainDao: DomainProfileDao = InMemoryDomainProfileDao()
    val behaviorDao: AppBehaviorProfileDao = InMemoryAppBehaviorProfileDao()
    val usageDao: AppUsageProfileDao = InMemoryAppUsageProfileDao()
    val appUsageStatsDao: AppUsageStatsDao = InMemoryAppUsageStatsDao()
    val overrideDao: UserOverrideDao = InMemoryUserOverrideDao()
    val userFeedbackDao: UserFeedbackDao = InMemoryUserFeedbackDao()
    val appReputationDao: AppReputationDao = InMemoryAppReputationDao()
}

private class InMemoryDomainProfileDao : DomainProfileDao {
    private val data = LinkedHashMap<String, DomainProfile>()

    override suspend fun get(domain: String): DomainProfile? = synchronized(data) { data[domain] }

    override suspend fun insert(profile: DomainProfile) {
        synchronized(data) { data[profile.domain] = profile }
    }

    override suspend fun update(profile: DomainProfile) {
        synchronized(data) { data[profile.domain] = profile }
    }
}

private class InMemoryAppBehaviorProfileDao : AppBehaviorProfileDao {
    private val data = LinkedHashMap<String, AppBehaviorProfile>()

    override suspend fun get(packageName: String): AppBehaviorProfile? = synchronized(data) {
        data[packageName]
    }

    override suspend fun upsert(profile: AppBehaviorProfile) {
        synchronized(data) { data[profile.packageName] = profile }
    }
}

private class InMemoryAppUsageProfileDao : AppUsageProfileDao {
    private val data = LinkedHashMap<String, AppUsageProfile>()

    override suspend fun get(packageName: String): AppUsageProfile? = synchronized(data) {
        data[packageName]
    }

    override suspend fun upsert(profile: AppUsageProfile) {
        synchronized(data) { data[profile.packageName] = profile }
    }
}

private class InMemoryUserOverrideDao : UserOverrideDao {
    private val data = ArrayList<UserOverride>()
    private var seq = 1L

    override suspend fun insert(override: UserOverride) {
        synchronized(data) {
            val row = if (override.id == 0L) override.copy(id = seq++) else override
            data.add(row)
        }
    }

    override suspend fun countFalsePositives(packageName: String): Int = synchronized(data) {
        data.count {
            it.packageName == packageName &&
                it.originalLabel.startsWith("PHISHING") &&
                it.correctedLabel != it.originalLabel
        }
    }
}

private class InMemoryAppUsageStatsDao : AppUsageStatsDao {
    private val data = LinkedHashMap<String, AppUsageStats>()

    override suspend fun get(packageName: String): AppUsageStats? = synchronized(data) {
        data[packageName]
    }

    override suspend fun upsert(stats: AppUsageStats) {
        synchronized(data) { data[stats.packageName] = stats }
    }

    override suspend fun resetDailyNotificationCounts() {
        synchronized(data) {
            data.keys.forEach { key ->
                data[key] = data[key]!!.copy(notificationCountToday = 0)
            }
        }
    }

    override suspend fun resetMonthlyOpenCounts() {
        synchronized(data) {
            data.keys.forEach { key ->
                data[key] = data[key]!!.copy(openCountMonth = 0)
            }
        }
    }
}

private class InMemoryUserFeedbackDao : UserFeedbackDao {
    private val data = LinkedHashMap<String, UserFeedback>()
    private var seq = 1L

    override suspend fun insertFeedback(feedback: UserFeedback) {
        synchronized(data) {
            val row = if (feedback.id == 0L) feedback.copy(id = seq++) else feedback
            data[row.notificationId] = row
        }
    }

    override suspend fun getFeedbackByDomain(domain: String): List<UserFeedback> = synchronized(data) {
        data.values.filter { it.domain == domain }.sortedByDescending { it.timestamp }
    }

    override suspend fun getFeedbackByPackage(packageName: String): List<UserFeedback> = synchronized(data) {
        data.values.filter { it.packageName == packageName }.sortedByDescending { it.timestamp }
    }

    override suspend fun countFeedbackByDomain(domain: String): Int = synchronized(data) {
        data.values.count { it.domain == domain }
    }

    override suspend fun countSafeOverridesForDomain(domain: String): Int = synchronized(data) {
        data.values.count { it.domain == domain && it.userClassification == SecurityLabel.SAFE_USEFUL.name }
    }

    override suspend fun countPhishingOverridesForDomain(domain: String): Int = synchronized(data) {
        data.values.count { it.domain == domain && it.userClassification == SecurityLabel.PHISHING.name }
    }

    override suspend fun getFeedbackByNotificationId(notificationId: String): UserFeedback? = synchronized(data) {
        data[notificationId]
    }

    override suspend fun getFeedbackByNotificationIds(notificationIds: List<String>): List<UserFeedback> =
        synchronized(data) {
            notificationIds.mapNotNull { data[it] }
        }

    override suspend fun countByPackageAndClassification(packageName: String, classification: String): Int =
        synchronized(data) {
            data.values.count { it.packageName == packageName && it.userClassification == classification }
        }

    override suspend fun countPhishingToSafeOverridesSince(sinceTimestamp: Long): Int =
        synchronized(data) {
            data.values.count {
                it.originalClassification == SecurityLabel.PHISHING.name &&
                    it.userClassification == SecurityLabel.SAFE_USEFUL.name &&
                    it.timestamp >= sinceTimestamp
            }
        }
}

private class InMemoryAppReputationDao : AppReputationDao {
    private val data = LinkedHashMap<String, AppReputation>()

    override suspend fun getByPackage(packageName: String): AppReputation? = synchronized(data) {
        data[packageName]
    }

    override suspend fun upsert(reputation: AppReputation) {
        synchronized(data) { data[reputation.packageName] = reputation }
    }
}
