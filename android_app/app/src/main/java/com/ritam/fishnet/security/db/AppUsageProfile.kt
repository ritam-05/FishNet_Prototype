package com.ritam.fishnet.security.db

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "app_usage_profiles")
data class AppUsageProfile(
    @PrimaryKey val packageName: String,
    val lastOpenedTime: Long,
    val lastNotificationTime: Long,
    val notificationCount: Int
)

