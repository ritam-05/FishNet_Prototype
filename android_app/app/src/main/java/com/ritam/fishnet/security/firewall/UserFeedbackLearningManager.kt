package com.ritam.fishnet.security.firewall

import com.ritam.fishnet.security.db.UserFeedbackDao

class UserFeedbackLearningManager(
    private val feedbackDao: UserFeedbackDao
) {
    suspend fun appMlWeight(packageName: String): Float {
        val safeOverrides = feedbackDao.countByPackageAndClassification(packageName, SecurityLabel.SAFE_USEFUL.name)
        val phishingOverrides = feedbackDao.countByPackageAndClassification(packageName, SecurityLabel.PHISHING.name)
        return when {
            safeOverrides >= 5 -> 0.85f
            phishingOverrides >= 3 -> 1.15f
            else -> 1f
        }
    }
}
