package com.ritam.fishnet.security.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update

@Dao
interface DomainProfileDao {
    @Query("SELECT * FROM domain_profiles WHERE domain = :domain LIMIT 1")
    suspend fun get(domain: String): DomainProfile?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(profile: DomainProfile)

    @Update
    suspend fun update(profile: DomainProfile)
}

