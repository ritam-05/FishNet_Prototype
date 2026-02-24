package com.ritam.fishnet

import android.content.Context
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

enum class AdBlockPolicy {
    ALWAYS_BLOCK,
    NEVER_BLOCK,
    USE_GLOBAL
}

object PerAppAdControlManager {
    private const val PREFS = "fishnet_per_app_ad_prefs"
    private const val KEY_BLOCKED_APPS = "blocked_apps"
    private const val KEY_WHITELISTED_APPS = "whitelisted_apps"

    private val lock = Mutex()
    private var appContext: Context? = null

    suspend fun initialize(context: Context) {
        lock.withLock {
            appContext = context.applicationContext
        }
    }

    suspend fun setAppPolicy(packageName: String, policy: AdBlockPolicy) {
        lock.withLock {
            val prefs = prefsLocked() ?: return
            val blocked = prefs.getStringSet(KEY_BLOCKED_APPS, emptySet())?.toMutableSet() ?: mutableSetOf()
            val whitelisted = prefs.getStringSet(KEY_WHITELISTED_APPS, emptySet())?.toMutableSet() ?: mutableSetOf()

            blocked.remove(packageName)
            whitelisted.remove(packageName)

            when (policy) {
                AdBlockPolicy.ALWAYS_BLOCK -> blocked.add(packageName)
                AdBlockPolicy.NEVER_BLOCK -> whitelisted.add(packageName)
                AdBlockPolicy.USE_GLOBAL -> Unit
            }
            prefs.edit()
                .putStringSet(KEY_BLOCKED_APPS, blocked)
                .putStringSet(KEY_WHITELISTED_APPS, whitelisted)
                .apply()
        }
    }

    suspend fun blockedApps(): Set<String> = lock.withLock {
        prefsLocked()?.getStringSet(KEY_BLOCKED_APPS, emptySet())?.toSet() ?: emptySet()
    }

    suspend fun whitelistedApps(): Set<String> = lock.withLock {
        prefsLocked()?.getStringSet(KEY_WHITELISTED_APPS, emptySet())?.toSet() ?: emptySet()
    }

    suspend fun shouldBlockAd(packageName: String, globalAdBlockEnabled: Boolean): Boolean {
        lock.withLock {
            val prefs = prefsLocked() ?: return false
            val blocked = prefs.getStringSet(KEY_BLOCKED_APPS, emptySet()) ?: emptySet()
            val whitelisted = prefs.getStringSet(KEY_WHITELISTED_APPS, emptySet()) ?: emptySet()

            if (packageName in whitelisted) return false
            if (packageName in blocked) return true
            if (!globalAdBlockEnabled) return false
            return AppSettings.isAutoDismissAdsEnabled(requireNotNull(appContext))
        }
    }

    private fun prefsLocked() = appContext?.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
}
