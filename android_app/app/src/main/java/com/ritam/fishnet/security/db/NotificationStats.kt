package com.ritam.fishnet.security.db

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "notification_stats")
data class NotificationStats(
    @PrimaryKey val id: Int = 1,
    val scannedToday: Int,
    val phishingToday: Int,
    val scamToday: Int,
    val spamToday: Int,
    val adsToday: Int,
    val totalPhishing: Int,
    val totalScam: Int,
    val totalAds: Int,
    val totalSpam: Int,
    val lastResetDate: String
)
