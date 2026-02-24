package com.ritam.fishnet.security.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query

@Dao
interface AppBehaviorProfileDao {
    @Query("SELECT * FROM app_behavior_profiles WHERE packageName = :packageName LIMIT 1")
    suspend fun get(packageName: String): AppBehaviorProfile?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(profile: AppBehaviorProfile)
}

