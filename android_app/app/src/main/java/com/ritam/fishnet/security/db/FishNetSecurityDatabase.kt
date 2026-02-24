package com.ritam.fishnet.security.db

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase

@Database(
    entities = [
        DomainProfile::class,
        AppBehaviorProfile::class,
        UserOverride::class,
        AppUsageProfile::class,
        NotificationStats::class,
        AppUsageStats::class,
        UserFeedback::class,
        AppReputation::class
    ],
    version = 4,
    exportSchema = false
)
abstract class FishNetSecurityDatabase : RoomDatabase() {
    abstract fun domainProfileDao(): DomainProfileDao
    abstract fun appBehaviorProfileDao(): AppBehaviorProfileDao
    abstract fun userOverrideDao(): UserOverrideDao
    abstract fun appUsageProfileDao(): AppUsageProfileDao
    abstract fun notificationStatsDao(): NotificationStatsDao
    abstract fun appUsageStatsDao(): AppUsageStatsDao
    abstract fun userFeedbackDao(): UserFeedbackDao
    abstract fun appReputationDao(): AppReputationDao

    companion object {
        @Volatile
        private var instance: FishNetSecurityDatabase? = null

        fun getInstance(context: Context): FishNetSecurityDatabase {
            val existing = instance
            if (existing != null) return existing
            return synchronized(this) {
                instance ?: Room.databaseBuilder(
                    context.applicationContext,
                    FishNetSecurityDatabase::class.java,
                    "fishnet_security.db"
                ).fallbackToDestructiveMigration().build().also { instance = it }
            }
        }
    }
}
