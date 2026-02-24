package com.ritam.fishnet.security.firewall

import java.util.Locale

data class EmailThreatDecision(
    val resolved: Boolean,
    val label: SecurityLabel?,
    val subtype: String?,
    val riskBoost: Float,
    val reason: String
)

class EmailThreatEngine {
    private val knownEmailPackages = setOf(
        "com.google.android.gm",
        "com.microsoft.office.outlook",
        "com.yahoo.mobile.client.android.mail",
        "com.samsung.android.email.provider"
    )

    private val safeKeywords = listOf(
        "otp", "one time password", "order receipt", "invoice", "newsletter",
        "account activity confirmation", "account activity", "password changed confirmation", "password changed"
    )
    private val adKeywords = listOf(
        "promotion", "sale", "discount", "cashback", "deal", "offer", "coupon", "promo code", "flash sale"
    )
    private val scamKeywords = listOf(
        "investment opportunity", "lottery winnings", "double your crypto", "crypto doubling",
        "loan approved", "loan approval", "job offer", "registration fee", "pay to process", "upfront payment"
    )
    private val credentialKeywords = listOf(
        "login", "verify login", "verify account", "confirm password", "share otp", "enter otp"
    )
    private val kycKeywords = listOf("kyc update", "submit pan", "aadhaar", "pan card", "identity verification")
    private val suspensionKeywords = listOf("account suspended", "account suspension", "suspend your account")
    private val urgentKeywords = listOf("urgent", "immediately", "act now", "within 24 hours", "final warning")
    private val paymentKeywords = listOf("payment", "card", "cvv", "upi", "bank details", "netbanking")

    fun isEmailApp(packageName: String): Boolean {
        val normalized = packageName.lowercase(Locale.ROOT)
        return knownEmailPackages.contains(normalized)
    }

    fun evaluate(
        text: String,
        packageName: String,
        signals: SignalFeatures,
        domain: DomainAnalysis
    ): EmailThreatDecision {
        val normalized = text.lowercase(Locale.ROOT)
        if (!isEmailApp(packageName)) {
            return EmailThreatDecision(
                resolved = false,
                label = null,
                subtype = null,
                riskBoost = 0f,
                reason = "Not an email app"
            )
        }

        var riskBoost = 0f
        if (signals.hasShortUrl || domain.hasShortenedUrl) {
            riskBoost += 0.15f
        }
        if (signals.hasUrgency && signals.hasUrl) {
            riskBoost += 0.15f
        }

        if (safeKeywords.any { normalized.contains(it) }) {
            return EmailThreatDecision(true, SecurityLabel.SAFE_USEFUL, null, riskBoost, "Email safe intent")
        }

        val hasSuspiciousUrl = domain.hasSuspiciousDomain || signals.hasShortUrl || domain.hasShortenedUrl
        if (adKeywords.any { normalized.contains(it) } && !hasSuspiciousUrl) {
            return EmailThreatDecision(true, SecurityLabel.IRRELEVANT_AD, null, riskBoost, "Email promotional intent")
        }

        val hasScam = scamKeywords.any { normalized.contains(it) }
        if (hasScam && !signals.hasCredentialRequest && credentialKeywords.none { normalized.contains(it) }) {
            return EmailThreatDecision(
                resolved = true,
                label = SecurityLabel.SCAM,
                subtype = detectScamSubtype(normalized),
                riskBoost = riskBoost,
                reason = "Email scam pattern"
            )
        }

        val hasCredentialAttempt = signals.hasCredentialRequest || credentialKeywords.any { normalized.contains(it) }
        val hasKyc = kycKeywords.any { normalized.contains(it) }
        val hasSuspension = suspensionKeywords.any { normalized.contains(it) }
        val hasUrgentLogin = urgentKeywords.any { normalized.contains(it) } &&
            (normalized.contains("login") || normalized.contains("verify"))
        val urlUrgencyCombo = signals.hasUrl && (signals.hasUrgency || urgentKeywords.any { normalized.contains(it) })
        if (hasCredentialAttempt || hasKyc || hasSuspension || hasUrgentLogin || urlUrgencyCombo) {
            return EmailThreatDecision(
                resolved = true,
                label = SecurityLabel.PHISHING,
                subtype = detectPhishingSubtype(normalized),
                riskBoost = riskBoost,
                reason = "Email phishing indicators"
            )
        }

        return EmailThreatDecision(
            resolved = false,
            label = null,
            subtype = null,
            riskBoost = riskBoost,
            reason = "Email uncertain - requires additional checks"
        )
    }

    private fun detectPhishingSubtype(normalized: String): String {
        return when {
            normalized.contains("login") || normalized.contains("verify account") || normalized.contains("password") ->
                "PHISHING_EMAIL_LOGIN"
            paymentKeywords.any { normalized.contains(it) } ->
                "PHISHING_EMAIL_PAYMENT"
            kycKeywords.any { normalized.contains(it) } ->
                "PHISHING_EMAIL_KYC"
            else -> "PHISHING_EMAIL_LOGIN"
        }
    }

    private fun detectScamSubtype(normalized: String): String {
        return when {
            normalized.contains("investment") || normalized.contains("crypto") -> "SCAM_INVESTMENT"
            normalized.contains("loan") -> "SCAM_LOAN"
            normalized.contains("lottery") || normalized.contains("winner") -> "SCAM_LOTTERY"
            normalized.contains("job offer") || normalized.contains("work from home") -> "SCAM_JOB"
            else -> "SCAM_INVESTMENT"
        }
    }
}
