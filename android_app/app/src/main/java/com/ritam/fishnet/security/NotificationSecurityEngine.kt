package com.ritam.fishnet.security

import java.util.Locale
import kotlin.math.max
import kotlin.math.min

enum class AppTier {
    SYSTEM,
    SOCIAL,
    FINANCIAL_TRUSTED,
    EMAIL,
    MEDIA,
    UNKNOWN
}

enum class NotificationIntentType {
    SOCIAL_INTERACTION,
    SYSTEM_STATUS,
    MEDIA_PLAYBACK,
    DELIVERY_UPDATE,
    CALENDAR_REMINDER,
    VERIFIED_BANK_TRANSACTION,
    TRANSACTION_RECEIPT,
    SPORTS_UPDATE,
    SOCIAL_BIRTHDAY,
    SOCIAL_REACTION,
    APP_STATUS_UPDATE,
    FINANCIAL_TRANSACTION,
    PROMOTION,
    EVENT_REMINDER,
    UNKNOWN
}

enum class LabelType {
    SAFE_USEFUL,
    IRRELEVANT,
    PHISHING_GENERAL,
    PHISHING_EMAIL_LOGIN,
    PHISHING_EMAIL_PAYMENT,
    PHISHING_EMAIL_KYC
}

data class ClassificationResult(
    val label: LabelType,
    val mlScore: Float,
    val signalCount: Int,
    val tier: AppTier,
    val intent: NotificationIntentType
)

private data class SignalFeatures(
    val hasUrl: Boolean,
    val hasShortUrl: Boolean,
    val hasActionVerb: Boolean,
    val hasUrgency: Boolean,
    val hasFinancialKeyword: Boolean,
    val hasCredentialRequest: Boolean,
    val isPromotion: Boolean
)

class NotificationSecurityEngine(
    private val mlClassifier: (String) -> Float
) {

    private val socialKeywords = listOf(
        "reacted", "liked", "commented", "shared", "birthday",
        "tagged", "mentioned", "friend request"
    )
    private val systemKeywords = listOf(
        "charging", "usb", "battery", "wifi", "bluetooth"
    )
    private val mediaKeywords = listOf(
        "now playing", "paused", "next track"
    )
    private val eventKeywords = listOf(
        "meeting", "calendar", "event", "reminder", "scheduled"
    )
    private val financialIntentKeywords = listOf(
        "debited", "credited", "upi", "rs.", "inr"
    )
    private val promotionKeywords = listOf(
        "sale", "discount", "cashback", "deal", "limited time"
    )
    private val actionVerbKeywords = listOf(
        "click", "verify", "login", "confirm", "update", "reset", "claim", "submit"
    )
    private val urgencyKeywords = listOf(
        "urgent", "immediately", "suspended", "last warning"
    )
    private val financialKeywords = listOf(
        "bank", "upi", "payment", "transfer", "debit", "credit", "transaction", "wallet"
    )
    private val credentialKeywords = listOf(
        "enter otp", "share otp", "confirm password"
    )

    private val urlRegex = Regex("""(http|https)://|www\.|\.com|\.net|\.org|\.in""")
    private val shortUrlRegex = Regex("""(bit\.ly|tinyurl|goo\.gl|t\.co|cutt\.ly)""")

    private val emailSafeKeywords = listOf(
        "otp",
        "invoice",
        "receipt",
        "password changed",
        "account activity confirmation",
        "account activity",
        "event reminder",
        "newsletter"
    )
    private val emailPromoKeywords = listOf(
        "promotion", "discount", "deal"
    )

    fun processNotification(text: String, packageName: String): ClassificationResult {
        val normalized = text.lowercase(Locale.ROOT)
        val tier = detectAppTier(packageName)
        val intent = detectIntentType(normalized)
        val signals = extractSignals(normalized)
        val signalCount = phishingSignalCount(signals, tier)

        // 1) Hard safe short-circuit.
        if (intent == NotificationIntentType.SOCIAL_INTERACTION ||
            intent == NotificationIntentType.SYSTEM_STATUS ||
            intent == NotificationIntentType.MEDIA_PLAYBACK ||
            intent == NotificationIntentType.EVENT_REMINDER
        ) {
            return result(
                label = LabelType.SAFE_USEFUL,
                mlScore = 0f,
                signalCount = signalCount,
                tier = tier,
                intent = intent
            )
        }
        if (tier == AppTier.SOCIAL && intent == NotificationIntentType.SOCIAL_INTERACTION) {
            return result(LabelType.SAFE_USEFUL, 0f, signalCount, tier, intent)
        }
        if (tier == AppTier.FINANCIAL_TRUSTED &&
            intent == NotificationIntentType.FINANCIAL_TRANSACTION
        ) {
            return result(LabelType.SAFE_USEFUL, 0f, signalCount, tier, intent)
        }

        // 2) Email safe rules.
        if (tier == AppTier.EMAIL) {
            if (emailSafeKeywords.any { normalized.contains(it) }) {
                return result(LabelType.SAFE_USEFUL, 0f, signalCount, tier, intent)
            }

            val suspiciousUrl = signals.hasUrl &&
                (signals.hasShortUrl || signals.hasActionVerb || signals.hasCredentialRequest || signals.hasUrgency)
            if (emailPromoKeywords.any { normalized.contains(it) } && !suspiciousUrl) {
                return result(LabelType.IRRELEVANT, 0f, signalCount, tier, intent)
            }
        }

        // 3) Spam check (spam is not phishing without theft intent).
        if (signals.isPromotion &&
            !signals.hasCredentialRequest &&
            signalCount < 2
        ) {
            return result(LabelType.IRRELEVANT, 0f, signalCount, tier, intent)
        }

        // 4) Phishing check with strict multi-signal gate.
        val mlScore = boundedProbability(mlClassifier(text))
        val threshold = thresholdFor(tier)
        val hasStrongIntent = signals.hasActionVerb || signals.hasCredentialRequest
        val canBePhishing = signalCount >= 2 && hasStrongIntent && mlScore >= threshold

        if (canBePhishing) {
            return result(
                label = determineSubtype(normalized, tier),
                mlScore = mlScore,
                signalCount = signalCount,
                tier = tier,
                intent = intent
            )
        }

        // 5) Default safe.
        return result(
            label = LabelType.SAFE_USEFUL,
            mlScore = mlScore,
            signalCount = signalCount,
            tier = tier,
            intent = intent
        )
    }

    fun detectAppTier(packageName: String): AppTier {
        val pkg = packageName.lowercase(Locale.ROOT)
        return when {
            pkg.startsWith("com.android.") ||
                pkg.startsWith("com.google.android.") ||
                pkg.startsWith("com.samsung.") -> AppTier.SYSTEM

            pkg.contains("facebook") ||
                pkg.contains("instagram") ||
                pkg.contains("whatsapp") ||
                pkg.contains("telegram") ||
                pkg.contains("linkedin") -> AppTier.SOCIAL

            pkg.contains("phonepe") ||
                pkg.contains("paytm") ||
                pkg.contains("paisa.user") ||
                pkg.contains("bank") -> AppTier.FINANCIAL_TRUSTED

            pkg.contains("gmail") ||
                pkg.contains("outlook") ||
                pkg.contains("yahoo") ||
                pkg.contains("mail") -> AppTier.EMAIL

            pkg.contains("spotify") ||
                pkg.contains("music") ||
                pkg.contains("youtube") -> AppTier.MEDIA

            else -> AppTier.UNKNOWN
        }
    }

    fun detectIntentType(normalizedText: String): NotificationIntentType {
        return when {
            socialKeywords.any { normalizedText.contains(it) } -> NotificationIntentType.SOCIAL_INTERACTION
            systemKeywords.any { normalizedText.contains(it) } -> NotificationIntentType.SYSTEM_STATUS
            mediaKeywords.any { normalizedText.contains(it) } -> NotificationIntentType.MEDIA_PLAYBACK
            eventKeywords.any { normalizedText.contains(it) } -> NotificationIntentType.EVENT_REMINDER
            financialIntentKeywords.any { normalizedText.contains(it) } -> NotificationIntentType.FINANCIAL_TRANSACTION
            promotionKeywords.any { normalizedText.contains(it) } -> NotificationIntentType.PROMOTION
            else -> NotificationIntentType.UNKNOWN
        }
    }

    private fun extractSignals(normalizedText: String): SignalFeatures {
        val hasUrl = urlRegex.containsMatchIn(normalizedText)
        val hasShortUrl = shortUrlRegex.containsMatchIn(normalizedText)
        val hasActionVerb = actionVerbKeywords.any { normalizedText.contains(it) }
        val hasUrgency = urgencyKeywords.any { normalizedText.contains(it) }
        val hasFinancialKeyword = financialKeywords.any { normalizedText.contains(it) }
        val hasCredentialRequest = credentialKeywords.any { normalizedText.contains(it) }
        val isPromotion = promotionKeywords.any { normalizedText.contains(it) }

        return SignalFeatures(
            hasUrl = hasUrl,
            hasShortUrl = hasShortUrl,
            hasActionVerb = hasActionVerb,
            hasUrgency = hasUrgency,
            hasFinancialKeyword = hasFinancialKeyword,
            hasCredentialRequest = hasCredentialRequest,
            isPromotion = isPromotion
        )
    }

    private fun phishingSignalCount(signals: SignalFeatures, tier: AppTier): Int {
        var count = 0
        if (signals.hasUrl) count++
        if (signals.hasActionVerb) count++
        if (signals.hasFinancialKeyword) count++
        if (signals.hasUrgency) count++
        if (tier == AppTier.UNKNOWN) count++
        return count
    }

    private fun thresholdFor(tier: AppTier): Float {
        return when (tier) {
            AppTier.EMAIL -> 0.75f
            AppTier.UNKNOWN -> 0.70f
            AppTier.SOCIAL -> 0.80f
            AppTier.FINANCIAL_TRUSTED -> 0.85f
            AppTier.SYSTEM -> 0.90f
            AppTier.MEDIA -> 0.90f
        }
    }

    private fun determineSubtype(normalizedText: String, tier: AppTier): LabelType {
        if (tier == AppTier.EMAIL) {
            if (normalizedText.contains("login") ||
                normalizedText.contains("password reset") ||
                normalizedText.contains("verify account")
            ) {
                return LabelType.PHISHING_EMAIL_LOGIN
            }
            if (normalizedText.contains("payment") ||
                normalizedText.contains("transaction") ||
                normalizedText.contains("upi") ||
                normalizedText.contains("transfer")
            ) {
                return LabelType.PHISHING_EMAIL_PAYMENT
            }
            if (normalizedText.contains("kyc") ||
                normalizedText.contains("pan") ||
                normalizedText.contains("aadhaar")
            ) {
                return LabelType.PHISHING_EMAIL_KYC
            }
        }
        return LabelType.PHISHING_GENERAL
    }

    private fun boundedProbability(value: Float): Float {
        return max(0f, min(1f, value))
    }

    private fun result(
        label: LabelType,
        mlScore: Float,
        signalCount: Int,
        tier: AppTier,
        intent: NotificationIntentType
    ): ClassificationResult {
        return ClassificationResult(
            label = label,
            mlScore = mlScore,
            signalCount = signalCount,
            tier = tier,
            intent = intent
        )
    }
}
