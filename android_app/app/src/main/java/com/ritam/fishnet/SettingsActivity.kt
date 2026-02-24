package com.ritam.fishnet

import android.content.Intent
import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.lifecycleScope
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.button.MaterialButton
import com.google.android.material.materialswitch.MaterialSwitch
import com.google.android.material.slider.Slider
import kotlinx.coroutines.launch

class SettingsActivity : AppCompatActivity() {

    private lateinit var viewModel: SettingsViewModel
    private lateinit var switchAggressive: MaterialSwitch
    private lateinit var sliderThreshold: Slider
    private lateinit var thresholdValue: android.widget.TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)

        viewModel = ViewModelProvider(this)[SettingsViewModel::class.java]

        switchAggressive = findViewById(R.id.switchAggressive)
        sliderThreshold = findViewById(R.id.sliderThreshold)
        thresholdValue = findViewById(R.id.tvThresholdValue)

        findViewById<MaterialToolbar>(R.id.toolbarSettings).setNavigationOnClickListener {
            finish()
        }
        bindListeners()
        observeSettings()
    }

    private fun bindListeners() {
        switchAggressive.setOnCheckedChangeListener { _, enabled ->
            viewModel.setAggressive(enabled)
        }
        sliderThreshold.addOnChangeListener { _, value, fromUser ->
            if (fromUser) {
                viewModel.setThreshold(value)
            }
        }
        findViewById<MaterialButton>(R.id.btnClearHistory).setOnClickListener {
            viewModel.clearHistory()
            Toast.makeText(this, "History cleared", Toast.LENGTH_SHORT).show()
        }
        findViewById<MaterialButton>(R.id.btnExportLogs).setOnClickListener {
            exportLogs()
        }
    }

    private fun observeSettings() {
        lifecycleScope.launch {
            viewModel.uiState.collect { state ->
                if (switchAggressive.isChecked != state.aggressiveEnabled) {
                    switchAggressive.isChecked = state.aggressiveEnabled
                }
                if (sliderThreshold.value != state.confidenceThreshold) {
                    sliderThreshold.value = state.confidenceThreshold
                }
                thresholdValue.text = String.format("%.2f", state.confidenceThreshold)
            }
        }
    }

    private fun exportLogs() {
        val payload = buildString {
            append("FishNet Scan Logs\n")
            append("package,category,subtype,timestamp,text\n")
            ScanRepository.getResults().forEach { row ->
                append(row.packageName).append(',')
                append(row.category).append(',')
                append(row.subtype.orEmpty().replace(',', ';')).append(',')
                append(row.timestamp).append(',')
                append(row.text.replace(',', ';').replace('\n', ' ')).append('\n')
            }
        }

        val sendIntent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_SUBJECT, "FishNet Logs")
            putExtra(Intent.EXTRA_TEXT, payload)
        }
        startActivity(Intent.createChooser(sendIntent, "Export FishNet logs"))
    }
}
