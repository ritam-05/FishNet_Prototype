package com.ritam.fishnet.security.firewall

import com.ritam.fishnet.security.AppTier

class RiskEngine {
    fun computeFinalRisk(
        mlScore: Float,
        phishingSignals: Int,
        anomalyScore: Float,
        domainRisk: Float,
        tier: AppTier
    ): Float {
        val tierRisk = tierRisk(tier)
        val normalizedSignals = (phishingSignals / 5f).coerceIn(0f, 1f)
        val finalRisk = (0.4f * mlScore.coerceIn(0f, 1f)) +
            (0.2f * normalizedSignals) +
            (0.15f * anomalyScore.coerceIn(0f, 1f)) +
            (0.15f * domainRisk.coerceIn(0f, 1f)) +
            (0.1f * tierRisk)
        return finalRisk.coerceIn(0f, 1f)
    }

    fun riskMeter(risk: Float): RiskMeter {
        return when {
            risk < 0.30f -> RiskMeter.SAFE
            risk < 0.55f -> RiskMeter.LOW
            risk < 0.75f -> RiskMeter.MEDIUM
            risk < 0.90f -> RiskMeter.HIGH
            else -> RiskMeter.CRITICAL
        }
    }

    private fun tierRisk(tier: AppTier): Float {
        return when (tier) {
            AppTier.SYSTEM -> 0.05f
            AppTier.SOCIAL -> 0.20f
            AppTier.FINANCIAL_TRUSTED -> 0.15f
            AppTier.EMAIL -> 0.35f
            AppTier.MEDIA -> 0.05f
            AppTier.UNKNOWN -> 1.00f
        }
    }
}

