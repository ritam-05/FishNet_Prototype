package com.ritam.fishnet

import android.content.Context
import java.util.Calendar
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONArray
import org.json.JSONObject

data class BlockedAdEntry(
    val packageName: String,
    val text: String,
    val timestamp: Long,
    val sourceType: String
)

object AdBlockHistoryManager {
    private const val PREFS = "fishnet_ad_block_history_prefs"
    private const val KEY_ENTRIES = "blocked_ad_entries"
    private const val MAX_AGE_MS = 24L * 60L * 60L * 1000L

    private val lock = Mutex()
    private var appContext: Context? = null
    private val state = MutableStateFlow<List<BlockedAdEntry>>(emptyList())
    val historyFlow: StateFlow<List<BlockedAdEntry>> = state.asStateFlow()

    suspend fun initialize(context: Context) {
        lock.withLock {
            appContext = context.applicationContext
            val persisted = readEntriesLocked()
            val pruned = pruneOlderThan24Hours(persisted)
            writeEntriesLocked(pruned)
            state.value = blockedToday(pruned)
        }
    }

    suspend fun recordBlockedAd(
        packageName: String,
        text: String,
        timestamp: Long = System.currentTimeMillis(),
        context: Context? = null,
        sourceType: String = SOURCE_GENERAL_AD
    ) {
        lock.withLock {
            if (appContext == null && context != null) {
                appContext = context.applicationContext
            }
            val current = readEntriesLocked().toMutableList()
            current.add(
                BlockedAdEntry(
                    packageName = packageName,
                    text = text,
                    timestamp = timestamp,
                    sourceType = sourceType
                )
            )
            val pruned = pruneOlderThan24Hours(current)
            writeEntriesLocked(pruned)
            state.value = blockedToday(pruned)
        }
    }

    private fun readEntriesLocked(): List<BlockedAdEntry> {
        val prefs = prefsLocked() ?: return emptyList()
        val raw = prefs.getString(KEY_ENTRIES, null) ?: return emptyList()
        return runCatching {
            val json = JSONArray(raw)
            buildList {
                for (i in 0 until json.length()) {
                    val obj = json.optJSONObject(i) ?: continue
                    val packageName = obj.optString("packageName")
                    val text = obj.optString("text")
                    val timestamp = obj.optLong("timestamp", 0L)
                    val sourceType = obj.optString("sourceType", SOURCE_LEGACY)
                    if (packageName.isBlank() || timestamp <= 0L) continue
                    add(
                        BlockedAdEntry(
                            packageName = packageName,
                            text = text,
                            timestamp = timestamp,
                            sourceType = sourceType
                        )
                    )
                }
            }
        }.getOrDefault(emptyList())
    }

    private fun writeEntriesLocked(entries: List<BlockedAdEntry>) {
        val prefs = prefsLocked() ?: return
        val json = JSONArray()
        entries.forEach { entry ->
            val obj = JSONObject()
            obj.put("packageName", entry.packageName)
            obj.put("text", entry.text)
            obj.put("timestamp", entry.timestamp)
            obj.put("sourceType", entry.sourceType)
            json.put(obj)
        }
        prefs.edit().putString(KEY_ENTRIES, json.toString()).apply()
    }

    private fun pruneOlderThan24Hours(entries: List<BlockedAdEntry>): List<BlockedAdEntry> {
        val now = System.currentTimeMillis()
        return entries.filter { entry ->
            val isFresh = now - entry.timestamp <= MAX_AGE_MS
            val normalizedPackage = entry.packageName.lowercase()
            val isWhatsApp = normalizedPackage == "com.whatsapp" || normalizedPackage == "com.whatsapp.w4b"
            val keepWhatsAppEntry = !isWhatsApp || entry.sourceType == SOURCE_WHATSAPP_UNKNOWN_AD
            isFresh && keepWhatsAppEntry
        }
    }

    private fun blockedToday(entries: List<BlockedAdEntry>): List<BlockedAdEntry> {
        val todayStart = todayStartMillis()
        return entries
            .filter { it.timestamp >= todayStart }
            .sortedByDescending { it.timestamp }
    }

    private fun todayStartMillis(): Long {
        val now = Calendar.getInstance()
        now.set(Calendar.HOUR_OF_DAY, 0)
        now.set(Calendar.MINUTE, 0)
        now.set(Calendar.SECOND, 0)
        now.set(Calendar.MILLISECOND, 0)
        return now.timeInMillis
    }

    private fun prefsLocked() = appContext?.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    private const val SOURCE_GENERAL_AD = "general_ad"
    const val SOURCE_WHATSAPP_UNKNOWN_AD = "whatsapp_unknown_ad"
    private const val SOURCE_LEGACY = "legacy"
}
