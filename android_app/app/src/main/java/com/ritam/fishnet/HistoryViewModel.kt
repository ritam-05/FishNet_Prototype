package com.ritam.fishnet

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class HistoryViewModel : ViewModel() {
    private val _results = MutableStateFlow<List<ScanResult>>(emptyList())
    val results: StateFlow<List<ScanResult>> = _results.asStateFlow()

    init {
        viewModelScope.launch {
            ScanRepository.resultsFlow.collect { data ->
                _results.value = UserFeedbackRepository.annotateWithFeedback(
                    data.sortedByDescending { it.timestamp }
                )
            }
        }
    }

    fun refreshAnnotatedResults() {
        viewModelScope.launch {
            val current = ScanRepository.getResults().sortedByDescending { it.timestamp }
            _results.value = UserFeedbackRepository.annotateWithFeedback(current)
        }
    }
}
