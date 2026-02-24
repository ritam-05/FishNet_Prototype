package com.ritam.fishnet.security.db

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "app_usage_stats")
data class AppUsageStats(
    @PrimaryKey val packageName: String,
    val openCountMonth: Int,
    val notificationCountToday: Int,
    val lastOpened: Long,
    val isLowPriority: Boolean
)
