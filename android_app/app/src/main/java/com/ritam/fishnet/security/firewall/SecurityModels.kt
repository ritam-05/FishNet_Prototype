package com.ritam.fishnet.security.firewall

import com.ritam.fishnet.security.AppTier
import com.ritam.fishnet.security.NotificationIntentType

enum class SecurityLabel {
    SAFE_USEFUL,
    IRRELEVANT_AD,
    SPAM,
    SCAM,
    PHISHING
}

enum class RiskMeter {
    SAFE,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
}

data class SignalFeatures(
    val hasUrl: Boolean,
    val hasShortUrl: Boolean,
    val hasActionVerb: Boolean,
    val hasUrgency: Boolean,
    val hasFinancialKeyword: Boolean,
    val hasCredentialRequest: Boolean,
    val isPromotion: Boolean
)

data class DomainAnalysis(
    val domains: List<String>,
    val domainRisk: Float,
    val hasSuspiciousDomain: Boolean,
    val hasShortenedUrl: Boolean
)

data class SecurityDecision(
    val label: SecurityLabel,
    val threatSubtype: String?,
    val finalRisk: Float,
    val mlScore: Float,
    val phishingSignals: Int,
    val spamSignals: Int,
    val tier: AppTier,
    val intent: NotificationIntentType,
    val riskMeter: RiskMeter,
    val shouldBlock: Boolean,
    val promptProtectedMode: Boolean,
    val lowPriorityBucket: Boolean,
    val reason: String,
    val adSignals: List<String> = emptyList()
)
