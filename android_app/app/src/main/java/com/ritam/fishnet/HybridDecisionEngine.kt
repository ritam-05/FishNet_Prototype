package com.ritam.fishnet

import android.content.Context
import java.util.Locale

enum class AppTier {
    SYSTEM_APPS,
    FINANCIAL_TRUSTED,
    SOCIAL_COMM,
    UNKNOWN_LOW_TRUST
}

enum class FinalLabel {
    SAFE_USEFUL,
    IRRELEVANT_AD,
    PHISHING_KYC,
    PHISHING_PAYMENT,
    PHISHING_LOGIN,
    PHISHING_GENERAL
}

data class RuleFeatures(
    val hasUrl: Boolean,
    val urgencyScore: Int,
    val numericDensity: Float,
    val otpPattern: Boolean,
    val transactionPattern: Boolean,
    val adPattern: Boolean,
    val normalizedText: String
)

data class FinalResult(
    val finalLabel: FinalLabel,
    val calibratedRisk: Float,
    val confidenceLevel: String,
    val appTier: AppTier
)

object AppTierResolver {

    private val systemPrefixes = listOf(
        "com.android.",
        "com.samsung.",
        "com.google.android."
    )

    private val systemExact = setOf(
        "com.google.android.gms"
    )

    private val financialExact = setOf(
        "com.phonepe.app",
        "com.google.android.apps.nbu.paisa.user",
        "com.paytm"
    )

    private val financialPrefixes = listOf(
        "com.sbi.",
        "com.icici.",
        "com.hdfc.",
        "com.axis.",
        "com.kotak.",
        "com.idfc."
    )

    private val socialExact = setOf(
        "com.whatsapp",
        "com.instagram.android",
        "com.facebook.katana",
        "org.telegram.messenger"
    )

    fun getAppTier(packageName: String): AppTier {
        val normalized = packageName.trim().lowercase(Locale.ROOT)
        if (normalized.isBlank()) return AppTier.UNKNOWN_LOW_TRUST

        if (normalized in systemExact || systemPrefixes.any { normalized.startsWith(it) }) {
            return AppTier.SYSTEM_APPS
        }
        if (normalized in financialExact || financialPrefixes.any { normalized.startsWith(it) }) {
            return AppTier.FINANCIAL_TRUSTED
        }
        if (normalized in socialExact) {
            return AppTier.SOCIAL_COMM
        }
        return AppTier.UNKNOWN_LOW_TRUST
    }
}

class RuleEngine {

    private val urlRegex = Regex(
        """\b((?:https?://|www\.)\S+|(?:\S+\.(?:com|net|org|in)\b)|(?:bit\.ly|tinyurl\.com|t\.co|cutt\.ly)\S*)"""
    )
    private val otpRegex = Regex(
        """\b(otp|verification code|one[\s-]*time password)\b.{0,30}(?<!\d)\d{4,8}(?!\d)"""
    )
    private val transactionRegex = Regex(
        """\b(debit(?:ed)?|credit(?:ed)?|upi|txn(?:\s*id)?|utr|imps|neft|balance)\b"""
    )
    private val adRegex = Regex(
        """\b(sale|offer|discount|cashback|buy now|limited time|promo|deal|shop now)\b"""
    )

    private val urgencyTerms = listOf(
        "urgent",
        "verify",
        "suspended",
        "blocked",
        "update now",
        "act now",
        "immediately",
        "final warning"
    )

    fun analyzeText(text: String): RuleFeatures {
        val normalized = text.trim().lowercase(Locale.ROOT)
        val hasUrl = urlRegex.containsMatchIn(normalized)
        val urgencyScore = urgencyTerms.count { normalized.contains(it) }
        val numericDensity = if (normalized.isBlank()) {
            0f
        } else {
            normalized.count { it.isDigit() }.toFloat() / normalized.length.toFloat()
        }
        val otpPattern = otpRegex.containsMatchIn(normalized)
        val transactionPattern = transactionRegex.containsMatchIn(normalized)
        val adPattern = adRegex.containsMatchIn(normalized)

        return RuleFeatures(
            hasUrl = hasUrl,
            urgencyScore = urgencyScore,
            numericDensity = numericDensity,
            otpPattern = otpPattern,
            transactionPattern = transactionPattern,
            adPattern = adPattern,
            normalizedText = normalized
        )
    }
}

class RiskScorer {

    fun score(phishingProbability: Float, appTier: AppTier, features: RuleFeatures): Float {
        var risk = phishingProbability.coerceIn(0f, 1f)

        when (appTier) {
            AppTier.SYSTEM_APPS -> risk *= 0.2f
            AppTier.FINANCIAL_TRUSTED -> {
                if (features.transactionPattern) risk *= 0.3f
            }
            AppTier.SOCIAL_COMM -> {
                if (features.hasUrl) risk += 0.15f
            }
            AppTier.UNKNOWN_LOW_TRUST -> {
                if (features.hasUrl) risk += 0.25f
            }
        }

        if (features.urgencyScore >= 2) {
            risk += 0.2f
        }

        return risk.coerceIn(0f, 1f)
    }
}

class FinalDecisionEngine {

    fun decide(
        risk: Float,
        phishingProbability: Float,
        features: RuleFeatures
    ): FinalLabel {
        if (risk < 0.20f) return FinalLabel.SAFE_USEFUL

        // Ad-like noise is suppressed unless model probability is extremely high.
        if (features.adPattern && phishingProbability <= 0.85f && risk < 0.70f) {
            return FinalLabel.IRRELEVANT_AD
        }

        if (features.adPattern && risk < 0.50f) {
            return FinalLabel.IRRELEVANT_AD
        }

        if (risk > PHISHING_SUBTYPE_MIN_RISK) {
            return phishingSubtype(features.normalizedText)
        }
        return FinalLabel.SAFE_USEFUL
    }

    fun confidenceBucket(risk: Float): String {
        return when {
            risk < 0.30f -> "Low Risk"
            risk < 0.60f -> "Moderate Risk"
            risk < 0.80f -> "High Risk"
            else -> "Critical Risk"
        }
    }

    private fun phishingSubtype(normalizedText: String): FinalLabel {
        return when {
            normalizedText.contains("kyc") ||
                normalizedText.contains("verify pan") ||
                normalizedText.contains("aadhaar") -> FinalLabel.PHISHING_KYC

            normalizedText.contains("pay") ||
                normalizedText.contains("transfer") ||
                normalizedText.contains("upi") -> FinalLabel.PHISHING_PAYMENT

            normalizedText.contains("login") ||
                normalizedText.contains("password reset") -> FinalLabel.PHISHING_LOGIN

            else -> FinalLabel.PHISHING_GENERAL
        }
    }
}

class HybridDecisionEngine(context: Context) {
    private val mlClassifier = MLClassifier.getInstance(context.applicationContext)
    private val ruleEngine = RuleEngine()
    private val riskScorer = RiskScorer()
    private val finalDecisionEngine = FinalDecisionEngine()

    fun processNotification(text: String, packageName: String): FinalResult {
        val appTier = AppTierResolver.getAppTier(packageName)
        val ruleFeatures = ruleEngine.analyzeText(text)
        val mlResult = mlClassifier.classify(text)

        val calibratedRisk = riskScorer.score(
            phishingProbability = mlResult.phishingProbability,
            appTier = appTier,
            features = ruleFeatures
        )
        val finalLabel = finalDecisionEngine.decide(
            risk = calibratedRisk,
            phishingProbability = mlResult.phishingProbability,
            features = ruleFeatures
        )
        val confidenceLevel = finalDecisionEngine.confidenceBucket(calibratedRisk)

        return FinalResult(
            finalLabel = finalLabel,
            calibratedRisk = calibratedRisk,
            confidenceLevel = confidenceLevel,
            appTier = appTier
        )
    }
}

private const val PHISHING_SUBTYPE_MIN_RISK = 0.50f
