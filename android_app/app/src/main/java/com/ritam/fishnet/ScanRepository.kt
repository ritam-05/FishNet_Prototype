package com.ritam.fishnet

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Prototype in-memory store. The API surface is intentionally simple so it can be
 * replaced by a Room-backed implementation later without changing call sites.
 */
object ScanRepository {

    data class ScanSummary(
        val total: Int,
        val useful: Int,
        val phishing: Int,
        val scam: Int,
        val irrelevant: Int
    )

    data class DashboardMetrics(
        val scannedToday: Int,
        val totalPhishingDetected: Int,
        val totalScamDetected: Int,
        val lastDetectedThreat: String?
    )

    private const val MAX_RESULTS = 2_000
    private const val MAX_PROCESSED_KEYS = 4_000

    private val lock = Any()
    private val results = ArrayList<ScanResult>(MAX_RESULTS)
    private val processedNotificationKeys = LinkedHashSet<String>(MAX_PROCESSED_KEYS)
    private val resultsFlowState = MutableStateFlow<List<ScanResult>>(emptyList())
    private val metricsFlowState = MutableStateFlow(
        DashboardMetrics(
            scannedToday = 0,
            totalPhishingDetected = 0,
            totalScamDetected = 0,
            lastDetectedThreat = null
        )
    )
    private var totalPhishingDetections = 0
    private var totalScamDetections = 0
    private val scanEventTimes = ArrayList<Long>(MAX_RESULTS)

    val resultsFlow: StateFlow<List<ScanResult>> = resultsFlowState.asStateFlow()
    val dashboardMetricsFlow: StateFlow<DashboardMetrics> = metricsFlowState.asStateFlow()

    fun addResult(result: ScanResult) {
        synchronized(lock) {
            if (results.size >= MAX_RESULTS) {
                results.removeAt(0)
            }
            results.add(result)
            resultsFlowState.value = results.toList()
        }
    }

    fun recordScan(timestamp: Long) {
        synchronized(lock) {
            if (scanEventTimes.size >= MAX_RESULTS) {
                scanEventTimes.removeAt(0)
            }
            scanEventTimes.add(timestamp)
            publishMetricsLocked(lastThreat = metricsFlowState.value.lastDetectedThreat)
        }
    }

    fun recordPhishingDetection(
        notificationId: String,
        packageName: String,
        text: String,
        timestamp: Long,
        phishingSubtype: String
    ) {
        synchronized(lock) {
            totalPhishingDetections += 1
            if (scanEventTimes.size >= MAX_RESULTS) {
                scanEventTimes.removeAt(0)
            }
            scanEventTimes.add(timestamp)
            if (results.size >= MAX_RESULTS) {
                results.removeAt(0)
            }
            results.add(
                ScanResult(
                    notificationId = notificationId,
                    packageName = packageName,
                    text = text,
                    category = ScanCategory.PHISHING.name,
                    subtype = phishingSubtype,
                    timestamp = timestamp,
                    feedbackClassification = null
                )
            )
            resultsFlowState.value = results.toList()
            val preview = text.take(44).replace('\n', ' ').trim()
            val threat = if (preview.isBlank()) {
                "$packageName: $phishingSubtype"
            } else {
                "$packageName: $phishingSubtype - $preview"
            }
            publishMetricsLocked(lastThreat = threat)
        }
    }

    fun recordScamDetection(
        notificationId: String,
        packageName: String,
        text: String,
        timestamp: Long,
        scamSubtype: String
    ) {
        synchronized(lock) {
            totalScamDetections += 1
            if (scanEventTimes.size >= MAX_RESULTS) {
                scanEventTimes.removeAt(0)
            }
            scanEventTimes.add(timestamp)
            if (results.size >= MAX_RESULTS) {
                results.removeAt(0)
            }
            results.add(
                ScanResult(
                    notificationId = notificationId,
                    packageName = packageName,
                    text = text,
                    category = ScanCategory.SCAM.name,
                    subtype = scamSubtype,
                    timestamp = timestamp,
                    feedbackClassification = null
                )
            )
            resultsFlowState.value = results.toList()
            val preview = text.take(44).replace('\n', ' ').trim()
            val threat = if (preview.isBlank()) {
                "$packageName: $scamSubtype"
            } else {
                "$packageName: $scamSubtype - $preview"
            }
            publishMetricsLocked(lastThreat = threat)
        }
    }

    fun getResults(): List<ScanResult> {
        synchronized(lock) {
            return results.toList()
        }
    }

    fun applyFeedbackOverride(notificationId: String, classification: ClassificationType): ScanResult? {
        synchronized(lock) {
            val index = results.indexOfFirst { it.notificationId == notificationId }
            if (index < 0) return null

            val current = results[index]
            if (current.feedbackClassification != null) return null
            val replacement = when (classification) {
                ClassificationType.PHISHING -> current.copy(
                    category = ScanCategory.PHISHING.name,
                    subtype = current.subtype ?: "PHISHING_GENERAL",
                    feedbackClassification = classification.name
                )
                ClassificationType.SCAM -> current.copy(
                    category = ScanCategory.SCAM.name,
                    subtype = current.subtype ?: "SCAM_GENERAL",
                    feedbackClassification = classification.name
                )
                ClassificationType.IRRELEVANT_AD -> current.copy(
                    category = ScanCategory.IRRELEVANT.name,
                    subtype = "Ad",
                    feedbackClassification = classification.name
                )
                ClassificationType.SPAM -> current.copy(
                    category = ScanCategory.IRRELEVANT.name,
                    subtype = "Spam",
                    feedbackClassification = classification.name
                )
                ClassificationType.SAFE_USEFUL -> current.copy(
                    category = ScanCategory.USEFUL.name,
                    subtype = null,
                    feedbackClassification = classification.name
                )
            }
            results[index] = replacement
            resultsFlowState.value = results.toList()
            return replacement
        }
    }

    fun refreshThreatPreview(packageName: String, subtype: String?, text: String) {
        synchronized(lock) {
            val preview = text.take(44).replace('\n', ' ').trim()
            val tag = subtype ?: "Updated"
            val threat = if (preview.isBlank()) {
                "$packageName: $tag"
            } else {
                "$packageName: $tag - $preview"
            }
            publishMetricsLocked(lastThreat = threat)
        }
    }

    fun markProcessed(notificationKey: String): Boolean {
        synchronized(lock) {
            if (processedNotificationKeys.contains(notificationKey)) {
                return false
            }
            if (processedNotificationKeys.size >= MAX_PROCESSED_KEYS) {
                val it = processedNotificationKeys.iterator()
                if (it.hasNext()) {
                    it.next()
                    it.remove()
                }
            }
            processedNotificationKeys.add(notificationKey)
            return true
        }
    }

    fun summarizeRange(fromTimestampInclusive: Long): ScanSummary {
        synchronized(lock) {
            val window = results.filter { it.timestamp >= fromTimestampInclusive }
            return ScanSummary(
                total = window.size,
                useful = window.count { it.category == ScanCategory.USEFUL.name },
                phishing = window.count { it.category == ScanCategory.PHISHING.name },
                scam = window.count { it.category == ScanCategory.SCAM.name },
                irrelevant = window.count { it.category == ScanCategory.IRRELEVANT.name }
            )
        }
    }

    fun clearAll() {
        synchronized(lock) {
            results.clear()
            processedNotificationKeys.clear()
            scanEventTimes.clear()
            resultsFlowState.value = emptyList()
            totalPhishingDetections = 0
            totalScamDetections = 0
            metricsFlowState.value = DashboardMetrics(0, 0, 0, null)
        }
    }

    private fun publishMetricsLocked(lastThreat: String?) {
        val todayStart = todayStartMillis()
        val scannedToday = scanEventTimes.count { it >= todayStart }
        metricsFlowState.value = DashboardMetrics(
            scannedToday = scannedToday,
            totalPhishingDetected = totalPhishingDetections,
            totalScamDetected = totalScamDetections,
            lastDetectedThreat = lastThreat
        )
    }

    private fun todayStartMillis(): Long {
        val now = java.util.Calendar.getInstance()
        now.set(java.util.Calendar.HOUR_OF_DAY, 0)
        now.set(java.util.Calendar.MINUTE, 0)
        now.set(java.util.Calendar.SECOND, 0)
        now.set(java.util.Calendar.MILLISECOND, 0)
        return now.timeInMillis
    }
}

data class ScanResult(
    val notificationId: String,
    val packageName: String,
    val text: String,
    val category: String,
    val subtype: String?,
    val timestamp: Long,
    val feedbackClassification: String? = null
)

enum class ScanCategory {
    PHISHING,
    SCAM,
    USEFUL,
    IRRELEVANT
}

fun ScanCategory.displayLabel(): String {
    return when (this) {
        ScanCategory.PHISHING -> "Phishing"
        ScanCategory.SCAM -> "Scam"
        ScanCategory.USEFUL -> "Useful"
        ScanCategory.IRRELEVANT -> "Ad / Promotional"
    }
}
