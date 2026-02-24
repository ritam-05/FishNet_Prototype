package com.ritam.fishnet.security.firewall

data class ScamDetectionResult(
    val isScam: Boolean,
    val subtype: String?,
    val escalateToMl: Boolean,
    val reason: String
)

class ScamDetector {
    private val investmentKeywords = listOf(
        "guaranteed returns", "double your money", "crypto profit", "forex signal", "trading signal"
    )
    private val loanKeywords = listOf(
        "instant loan approved", "no documents required", "pre-approved loan", "low interest loan"
    )
    private val lotteryKeywords = listOf(
        "you won", "claim reward", "lucky draw winner", "lottery winnings"
    )
    private val jobKeywords = listOf(
        "work from home", "easy income", "registration fee required", "job offer requiring payment"
    )
    private val romanceKeywords = listOf(
        "send money urgently", "need help transfer funds"
    )
    private val credentialKeywords = listOf(
        "login", "verify account", "enter otp", "share otp", "password", "pin", "cvv", "kyc", "pan", "aadhaar"
    )

    fun detect(normalizedText: String, signals: SignalFeatures, suspiciousUrl: Boolean): ScamDetectionResult {
        val subtype = when {
            investmentKeywords.any { normalizedText.contains(it) } -> "SCAM_INVESTMENT"
            loanKeywords.any { normalizedText.contains(it) } -> "SCAM_LOAN"
            lotteryKeywords.any { normalizedText.contains(it) } -> "SCAM_LOTTERY"
            jobKeywords.any { normalizedText.contains(it) } -> "SCAM_JOB"
            romanceKeywords.any { normalizedText.contains(it) } -> "SCAM_ROMANCE"
            else -> null
        }
        if (subtype == null) {
            return ScamDetectionResult(false, null, false, "No scam indicators")
        }

        val hasCredentialTheft = signals.hasCredentialRequest || credentialKeywords.any { normalizedText.contains(it) }
        val escalateToMl = (suspiciousUrl || signals.hasShortUrl || signals.hasUrl) && hasCredentialTheft ||
            (suspiciousUrl && signals.hasUrl) ||
            hasCredentialTheft
        if (escalateToMl) {
            return ScamDetectionResult(
                isScam = false,
                subtype = subtype,
                escalateToMl = true,
                reason = "Scam content with link/credential overlap"
            )
        }

        return ScamDetectionResult(
            isScam = true,
            subtype = subtype,
            escalateToMl = false,
            reason = "Scam keyword pattern matched"
        )
    }
}
