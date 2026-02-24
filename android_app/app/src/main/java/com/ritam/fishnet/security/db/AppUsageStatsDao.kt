package com.ritam.fishnet.security.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query

@Dao
interface AppUsageStatsDao {
    @Query("SELECT * FROM app_usage_stats WHERE packageName = :packageName LIMIT 1")
    suspend fun get(packageName: String): AppUsageStats?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(stats: AppUsageStats)

    @Query("UPDATE app_usage_stats SET notificationCountToday = 0")
    suspend fun resetDailyNotificationCounts()

    @Query("UPDATE app_usage_stats SET openCountMonth = 0")
    suspend fun resetMonthlyOpenCounts()
}
