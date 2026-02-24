package com.ritam.fishnet

data class DailyRiskMeter(
    val score: Float,
    val level: String
)

object RiskMeterCalculator {
    fun calculate(phishingToday: Int, scamToday: Int, spamToday: Int): DailyRiskMeter {
        val score = (phishingToday * 0.6f) + (scamToday * 0.3f) + (spamToday * 0.1f)
        val level = when {
            score <= 2f -> "LOW"
            score <= 5f -> "MEDIUM"
            else -> "HIGH"
        }
        return DailyRiskMeter(score = score, level = level)
    }
}
