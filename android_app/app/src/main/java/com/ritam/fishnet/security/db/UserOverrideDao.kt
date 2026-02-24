package com.ritam.fishnet.security.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query

@Dao
interface UserOverrideDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(override: UserOverride)

    @Query(
        """
        SELECT COUNT(*) FROM user_overrides
        WHERE packageName = :packageName
          AND originalLabel LIKE 'PHISHING%'
          AND correctedLabel != originalLabel
        """
    )
    suspend fun countFalsePositives(packageName: String): Int
}

