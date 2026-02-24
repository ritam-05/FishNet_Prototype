package com.ritam.fishnet.security.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query

@Dao
interface UserFeedbackDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertFeedback(feedback: UserFeedback)

    @Query("SELECT * FROM user_feedback WHERE domain = :domain ORDER BY timestamp DESC")
    suspend fun getFeedbackByDomain(domain: String): List<UserFeedback>

    @Query("SELECT * FROM user_feedback WHERE packageName = :packageName ORDER BY timestamp DESC")
    suspend fun getFeedbackByPackage(packageName: String): List<UserFeedback>

    @Query("SELECT COUNT(*) FROM user_feedback WHERE domain = :domain")
    suspend fun countFeedbackByDomain(domain: String): Int

    @Query("SELECT COUNT(*) FROM user_feedback WHERE domain = :domain AND userClassification = 'SAFE_USEFUL'")
    suspend fun countSafeOverridesForDomain(domain: String): Int

    @Query("SELECT COUNT(*) FROM user_feedback WHERE domain = :domain AND userClassification = 'PHISHING'")
    suspend fun countPhishingOverridesForDomain(domain: String): Int

    @Query("SELECT * FROM user_feedback WHERE notificationId = :notificationId LIMIT 1")
    suspend fun getFeedbackByNotificationId(notificationId: String): UserFeedback?

    @Query("SELECT * FROM user_feedback WHERE notificationId IN (:notificationIds)")
    suspend fun getFeedbackByNotificationIds(notificationIds: List<String>): List<UserFeedback>

    @Query("SELECT COUNT(*) FROM user_feedback WHERE packageName = :packageName AND userClassification = :classification")
    suspend fun countByPackageAndClassification(packageName: String, classification: String): Int

    @Query(
        """
        SELECT COUNT(*) FROM user_feedback
        WHERE originalClassification = 'PHISHING'
          AND userClassification = 'SAFE_USEFUL'
          AND timestamp >= :sinceTimestamp
        """
    )
    suspend fun countPhishingToSafeOverridesSince(sinceTimestamp: Long): Int
}
