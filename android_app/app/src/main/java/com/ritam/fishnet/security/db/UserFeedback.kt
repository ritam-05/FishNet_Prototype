package com.ritam.fishnet.security.db

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(
    tableName = "user_feedback",
    indices = [
        Index(value = ["notificationId"], unique = true),
        Index(value = ["packageName"]),
        Index(value = ["domain"])
    ]
)
data class UserFeedback(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val notificationId: String,
    val packageName: String,
    val domain: String?,
    val originalClassification: String,
    val userClassification: String,
    val timestamp: Long
)
