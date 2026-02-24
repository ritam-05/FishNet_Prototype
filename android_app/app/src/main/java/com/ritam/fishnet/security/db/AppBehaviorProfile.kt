package com.ritam.fishnet.security.db

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "app_behavior_profiles")
data class AppBehaviorProfile(
    @PrimaryKey val packageName: String,
    val avgNotificationsPerDay: Float,
    val avgUrlRate: Float,
    val avgActionVerbRate: Float,
    val lastSeenTime: Long,
    val totalNotifications: Int
)

