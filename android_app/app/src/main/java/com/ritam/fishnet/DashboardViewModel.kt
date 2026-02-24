package com.ritam.fishnet

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

data class DashboardUiState(
    val scannedToday: Int = 0,
    val phishingToday: Int = 0,
    val scamToday: Int = 0,
    val spamToday: Int = 0,
    val adsToday: Int = 0,
    val phishingTotal: Int = 0,
    val scamTotal: Int = 0,
    val adsTotal: Int = 0,
    val spamTotal: Int = 0,
    val adsBlockedTotal: Int = 0,
    val adSuppressionEfficiencyPercent: Int = 0,
    val autoBlockPromotionsEnabled: Boolean = true,
    val riskScore: Float = 0f,
    val riskLevel: String = "LOW",
    val lastThreatText: String = "No recent threats"
)

class DashboardViewModel : ViewModel() {
    private val _uiState = MutableStateFlow(DashboardUiState())
    val uiState: StateFlow<DashboardUiState> = _uiState.asStateFlow()

    init {
        viewModelScope.launch {
            NotificationStatsRepository.statsFlow.collect { stats ->
                val current = _uiState.value
                val risk = RiskMeterCalculator.calculate(
                    phishingToday = stats.phishingToday,
                    scamToday = stats.scamToday,
                    spamToday = stats.spamToday
                )
                _uiState.value = current.copy(
                    scannedToday = stats.scannedToday,
                    phishingToday = stats.phishingToday,
                    scamToday = stats.scamToday,
                    spamToday = stats.spamToday,
                    adsToday = stats.adsToday,
                    phishingTotal = stats.totalPhishing,
                    scamTotal = stats.totalScam,
                    adsTotal = stats.totalAds,
                    spamTotal = stats.totalSpam,
                    riskScore = risk.score,
                    riskLevel = risk.level
                )
            }
        }
        viewModelScope.launch {
            ScanRepository.dashboardMetricsFlow.collect { metrics ->
                val current = _uiState.value
                _uiState.value = current.copy(
                    lastThreatText = metrics.lastDetectedThreat ?: "No recent threats"
                )
            }
        }
        viewModelScope.launch {
            AdStatsManager.statsFlow.collect { adStats ->
                val current = _uiState.value
                _uiState.value = current.copy(
                    adsBlockedTotal = adStats.totalAdsBlocked,
                    adSuppressionEfficiencyPercent = adStats.suppressionEfficiencyPercent
                )
            }
        }
    }
}
