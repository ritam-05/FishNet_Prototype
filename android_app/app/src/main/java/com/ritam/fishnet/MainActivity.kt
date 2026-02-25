package com.ritam.fishnet

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.util.Log
import android.view.View
import android.widget.ArrayAdapter
import android.widget.AutoCompleteTextView
import android.widget.Button
import android.widget.ImageView
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.lifecycleScope
import com.google.android.material.materialswitch.MaterialSwitch
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {

    private lateinit var viewModel: DashboardViewModel

    private lateinit var ivShield: ImageView
    private lateinit var tvProtectionStatus: TextView
    private lateinit var tvScannedToday: TextView
    private lateinit var tvPhishingToday: TextView
    private lateinit var tvScamToday: TextView
    private lateinit var tvSpamToday: TextView
    private lateinit var tvAdsToday: TextView
    private lateinit var dropdownAdsBlockedToday: AutoCompleteTextView
    private lateinit var adsBlockedAdapter: ArrayAdapter<String>
    private lateinit var tvAdSuppressionEfficiency: TextView
    private lateinit var tvRiskMeter: TextView
    private lateinit var tvLastThreat: TextView
    private lateinit var btnGrantAccess: Button
    private lateinit var switchProtection: MaterialSwitch
    private lateinit var switchAutoBlockAds: MaterialSwitch

    private val postNotificationPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) {}

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        viewModel = ViewModelProvider(this)[DashboardViewModel::class.java]
        bindViews()
        bindClicks()
        lifecycleScope.launch {
            NotificationStatsRepository.initialize(applicationContext)
            UserFeedbackRepository.initialize(applicationContext)
            AdStatsManager.initialize(applicationContext)
            PerAppAdControlManager.initialize(applicationContext)
            AdBlockHistoryManager.initialize(applicationContext)
        }

        requestPostNotificationPermissionIfNeeded()
        handleNotificationLaunchIntent(intent)
        observeDashboardState()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleNotificationLaunchIntent(intent)
    }

    override fun onResume() {
        super.onResume()
        updateProtectionStatusUi()
        triggerStartupScanIfListenerEnabled()
    }

    private fun bindViews() {
        ivShield = findViewById(R.id.ivShield)
        tvProtectionStatus = findViewById(R.id.tvProtectionStatus)
        tvScannedToday = findViewById(R.id.tvScannedToday)
        tvPhishingToday = findViewById(R.id.tvPhishingToday)
        tvScamToday = findViewById(R.id.tvScamToday)
        tvSpamToday = findViewById(R.id.tvSpamToday)
        tvAdsToday = findViewById(R.id.tvAdsToday)
        dropdownAdsBlockedToday = findViewById(R.id.dropdownAdsBlockedToday)
        tvAdSuppressionEfficiency = findViewById(R.id.tvAdSuppressionEfficiency)
        tvRiskMeter = findViewById(R.id.tvRiskMeter)
        tvLastThreat = findViewById(R.id.tvLastThreat)
        btnGrantAccess = findViewById(R.id.btnGrantAccess)
        switchProtection = findViewById(R.id.switchProtection)
        switchAutoBlockAds = findViewById(R.id.switchAutoBlockAds)
        adsBlockedAdapter = ArrayAdapter(
            this,
            android.R.layout.simple_dropdown_item_1line,
            mutableListOf()
        )
        dropdownAdsBlockedToday.setAdapter(adsBlockedAdapter)
    }

    private fun bindClicks() {
        findViewById<Button>(R.id.btnViewHistory).setOnClickListener {
            startActivity(Intent(this, HistoryActivity::class.java))
        }
        findViewById<Button>(R.id.btnSettings).setOnClickListener {
            startActivity(Intent(this, SettingsActivity::class.java))
        }
        btnGrantAccess.setOnClickListener {
            startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))
        }
        switchProtection.setOnCheckedChangeListener { _, enabled ->
            AppSettings.setProtectionEnabled(this, enabled)
            updateProtectionStatusUi()
        }
        if (switchAutoBlockAds.isChecked != AppSettings.isAutoDismissAdsEnabled(this)) {
            switchAutoBlockAds.isChecked = AppSettings.isAutoDismissAdsEnabled(this)
        }
        switchAutoBlockAds.setOnCheckedChangeListener { _, enabled ->
            AppSettings.setGlobalAdBlockEnabled(this, enabled)
            AppSettings.setAutoDismissAdsEnabled(this, enabled)
        }
    }

    private fun observeDashboardState() {
        lifecycleScope.launch {
            viewModel.uiState.collect { state ->
                tvScannedToday.text = state.scannedToday.toString()
                tvPhishingToday.text = state.phishingToday.toString()
                tvScamToday.text = state.scamToday.toString()
                tvSpamToday.text = state.spamToday.toString()
                tvAdsToday.text = state.adsBlockedTotal.toString()
                val blockedItems = if (state.blockedAdsToday.isEmpty()) {
                    listOf(getString(R.string.no_blocked_ads_today))
                } else {
                    state.blockedAdsToday
                }
                adsBlockedAdapter.clear()
                adsBlockedAdapter.addAll(blockedItems)
                adsBlockedAdapter.notifyDataSetChanged()
                dropdownAdsBlockedToday.setText(blockedItems.first(), false)
                tvAdSuppressionEfficiency.text = "${state.adSuppressionEfficiencyPercent}%"
                tvRiskMeter.text = "${state.riskLevel} (${String.format("%.1f", state.riskScore)})"
                val riskColor = when (state.riskLevel) {
                    "LOW" -> R.color.safe_green
                    "MEDIUM" -> R.color.risk_yellow
                    else -> R.color.phishing_red
                }
                tvRiskMeter.setTextColor(ContextCompat.getColor(this@MainActivity, riskColor))
                tvLastThreat.text = state.lastThreatText
            }
        }
    }

    private fun requestPostNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        if (ContextCompat.checkSelfPermission(
                this,
                Manifest.permission.POST_NOTIFICATIONS
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            postNotificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    private fun isNotificationAccessEnabled(): Boolean {
        val enabledListeners = Settings.Secure.getString(
            contentResolver,
            "enabled_notification_listeners"
        ) ?: ""
        return enabledListeners.contains(packageName)
    }

    private fun updateProtectionStatusUi() {
        val accessEnabled = isNotificationAccessEnabled()
        val enabled = accessEnabled && AppSettings.isProtectionEnabled(this)
        if (switchProtection.isChecked != AppSettings.isProtectionEnabled(this)) {
            switchProtection.isChecked = AppSettings.isProtectionEnabled(this)
        }
        if (switchAutoBlockAds.isChecked != AppSettings.isAutoDismissAdsEnabled(this)) {
            switchAutoBlockAds.isChecked = AppSettings.isAutoDismissAdsEnabled(this)
        }
        tvProtectionStatus.text = getString(
            if (enabled) R.string.protection_on else R.string.protection_off
        )
        tvProtectionStatus.setTextColor(
            ContextCompat.getColor(
                this,
                if (enabled) R.color.safe_green else R.color.irrelevant_gray
            )
        )
        ivShield.alpha = if (enabled) 1f else 0.55f
        btnGrantAccess.visibility = if (accessEnabled) View.GONE else View.VISIBLE
    }

    private fun triggerStartupScanIfListenerEnabled() {
        if (!isNotificationAccessEnabled()) return
        if (!AppSettings.isProtectionEnabled(this)) return
        val scanIntent = Intent(this, NotificationService::class.java).apply {
            action = NotificationService.ACTION_SCAN_EXISTING_NOTIFICATIONS
        }
        startService(scanIntent)
    }

    private fun handleNotificationLaunchIntent(intent: Intent?) {
        if (intent?.action != NotificationService.ACTION_OPEN_FROM_NOTIFICATION) return
        val source = intent.getStringExtra(NotificationService.EXTRA_OPEN_SOURCE).orEmpty()
        val packageName = intent.getStringExtra(NotificationService.EXTRA_SOURCE_PACKAGE).orEmpty()
        val promptProtectedMode = intent.getBooleanExtra(
            NotificationService.EXTRA_PROMPT_PROTECTED_MODE,
            false
        )
        Log.d(
            TAG,
            "Opened from notification source=$source package=$packageName protectedModePrompt=$promptProtectedMode"
        )
    }

    companion object {
        private const val TAG = "MainActivity"
    }
}
