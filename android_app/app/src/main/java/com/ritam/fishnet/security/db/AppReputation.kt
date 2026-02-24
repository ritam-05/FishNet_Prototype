package com.ritam.fishnet.security.db

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "app_reputation")
data class AppReputation(
    @PrimaryKey val packageName: String,
    val safeOverrides: Int,
    val phishingOverrides: Int,
    val riskAdjustment: Float
)
