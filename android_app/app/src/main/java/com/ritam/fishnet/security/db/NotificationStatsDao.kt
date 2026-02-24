package com.ritam.fishnet.security.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query

@Dao
interface NotificationStatsDao {
    @Query("SELECT * FROM notification_stats WHERE id = 1 LIMIT 1")
    suspend fun get(): NotificationStats?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(stats: NotificationStats)
}

