package com.ritam.fishnet.security.db

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "domain_profiles")
data class DomainProfile(
    @PrimaryKey val domain: String,
    val timesSeen: Int,
    val averageRisk: Float,
    val flaggedCount: Int
)

