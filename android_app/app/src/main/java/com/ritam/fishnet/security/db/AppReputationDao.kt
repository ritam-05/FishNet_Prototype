package com.ritam.fishnet.security.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query

@Dao
interface AppReputationDao {
    @Query("SELECT * FROM app_reputation WHERE packageName = :packageName LIMIT 1")
    suspend fun getByPackage(packageName: String): AppReputation?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(reputation: AppReputation)
}
