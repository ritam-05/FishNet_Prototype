package com.ritam.fishnet

import android.content.Context

object AppSettings {
    private const val PREFS = "fishnet_prefs"
    private const val KEY_AGGRESSIVE = "aggressive_detection"
    private const val KEY_THRESHOLD = "confidence_threshold"
    private const val KEY_PROTECTION_ENABLED = "protection_enabled"
    private const val KEY_BLOCKING_ENABLED = "blocking_enabled"
    private const val KEY_LOW_PRIORITY_SUPPRESSION = "low_priority_suppression"
    private const val KEY_GLOBAL_AD_BLOCK_ENABLED = "global_ad_block_enabled"
    private const val KEY_AUTO_DISMISS_ADS = "auto_dismiss_ads"

    fun isAggressiveEnabled(context: Context): Boolean {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getBoolean(KEY_AGGRESSIVE, false)
    }

    fun setAggressiveEnabled(context: Context, enabled: Boolean) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(KEY_AGGRESSIVE, enabled)
            .apply()
    }

    fun getConfidenceThreshold(context: Context): Float {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getFloat(KEY_THRESHOLD, 0.75f)
            .coerceIn(0.5f, 0.95f)
    }

    fun setConfidenceThreshold(context: Context, threshold: Float) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putFloat(KEY_THRESHOLD, threshold.coerceIn(0.5f, 0.95f))
            .apply()
    }

    fun isProtectionEnabled(context: Context): Boolean {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getBoolean(KEY_PROTECTION_ENABLED, true)
    }

    fun setProtectionEnabled(context: Context, enabled: Boolean) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(KEY_PROTECTION_ENABLED, enabled)
            .apply()
    }

    fun isBlockingEnabled(context: Context): Boolean {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getBoolean(KEY_BLOCKING_ENABLED, false)
    }

    fun setBlockingEnabled(context: Context, enabled: Boolean) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(KEY_BLOCKING_ENABLED, enabled)
            .apply()
    }

    fun isLowPrioritySuppressionEnabled(context: Context): Boolean {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getBoolean(KEY_LOW_PRIORITY_SUPPRESSION, true)
    }

    fun setLowPrioritySuppressionEnabled(context: Context, enabled: Boolean) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(KEY_LOW_PRIORITY_SUPPRESSION, enabled)
            .apply()
    }

    fun isGlobalAdBlockEnabled(context: Context): Boolean {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getBoolean(KEY_GLOBAL_AD_BLOCK_ENABLED, true)
    }

    fun setGlobalAdBlockEnabled(context: Context, enabled: Boolean) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(KEY_GLOBAL_AD_BLOCK_ENABLED, enabled)
            .apply()
    }

    fun isAutoDismissAdsEnabled(context: Context): Boolean {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getBoolean(KEY_AUTO_DISMISS_ADS, true)
    }

    fun setAutoDismissAdsEnabled(context: Context, enabled: Boolean) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(KEY_AUTO_DISMISS_ADS, enabled)
            .apply()
    }
}
