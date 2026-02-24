package com.ritam.fishnet

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

data class SettingsUiState(
    val aggressiveEnabled: Boolean = false,
    val confidenceThreshold: Float = 0.75f
)

class SettingsViewModel(application: Application) : AndroidViewModel(application) {

    private val _uiState = MutableStateFlow(
        SettingsUiState(
            aggressiveEnabled = AppSettings.isAggressiveEnabled(application),
            confidenceThreshold = AppSettings.getConfidenceThreshold(application)
        )
    )
    val uiState: StateFlow<SettingsUiState> = _uiState.asStateFlow()

    fun setAggressive(enabled: Boolean) {
        AppSettings.setAggressiveEnabled(getApplication(), enabled)
        _uiState.value = _uiState.value.copy(aggressiveEnabled = enabled)
    }

    fun setThreshold(threshold: Float) {
        val rounded = (threshold * 100).toInt() / 100f
        AppSettings.setConfidenceThreshold(getApplication(), rounded)
        _uiState.value = _uiState.value.copy(confidenceThreshold = rounded)
    }

    fun clearHistory() {
        ScanRepository.clearAll()
    }
}
