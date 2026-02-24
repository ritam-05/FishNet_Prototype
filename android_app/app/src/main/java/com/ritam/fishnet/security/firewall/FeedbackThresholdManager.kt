package com.ritam.fishnet.security.firewall

import com.ritam.fishnet.security.AppTier
import com.ritam.fishnet.security.db.UserOverride
import com.ritam.fishnet.security.db.UserOverrideDao

class FeedbackThresholdManager(
    private val userOverrideDao: UserOverrideDao
) {
    suspend fun thresholdFor(packageName: String, tier: AppTier): Float {
        val base = when (tier) {
            AppTier.EMAIL -> 0.75f
            AppTier.UNKNOWN -> 0.70f
            AppTier.SOCIAL -> 0.80f
            AppTier.FINANCIAL_TRUSTED -> 0.85f
            AppTier.SYSTEM -> 1.10f
            AppTier.MEDIA -> 1.10f
        }
        val falsePositives = userOverrideDao.countFalsePositives(packageName)
        val adaptiveBoost = (falsePositives * 0.01f).coerceAtMost(0.08f)
        return (base + adaptiveBoost).coerceAtMost(0.95f)
    }

    suspend fun recordOverride(
        packageName: String,
        originalLabel: String,
        correctedLabel: String,
        timestamp: Long
    ) {
        userOverrideDao.insert(
            UserOverride(
                packageName = packageName,
                originalLabel = originalLabel,
                correctedLabel = correctedLabel,
                timestamp = timestamp
            )
        )
    }
}

