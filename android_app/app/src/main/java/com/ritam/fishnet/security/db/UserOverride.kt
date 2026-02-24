package com.ritam.fishnet.security.db

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "user_overrides")
data class UserOverride(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val packageName: String,
    val originalLabel: String,
    val correctedLabel: String,
    val timestamp: Long
)

