package com.ritam.fishnet.security.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query

@Dao
interface AppUsageProfileDao {
    @Query("SELECT * FROM app_usage_profiles WHERE packageName = :packageName LIMIT 1")
    suspend fun get(packageName: String): AppUsageProfile?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(profile: AppUsageProfile)
}

