package com.ritam.fishnet.security.firewall

class SignalExtractor {
    private val urlRegex = Regex("""(http|https)://|www\.|[a-z0-9-]+\.(com|net|org|in|xyz|top|live|click|ru|tk|ml|ga|cf)""")
    private val shortUrlRegex = Regex("""(bit\.ly|tinyurl|goo\.gl|t\.co|cutt\.ly)""")

    private val actionVerbKeywords = listOf(
        "click", "verify", "login", "confirm", "update", "reset", "claim", "submit"
    )
    private val urgencyKeywords = listOf(
        "urgent", "immediately", "suspended", "last warning", "act now"
    )
    private val financialKeywords = listOf(
        "bank", "upi", "payment", "transfer", "debit", "credit", "transaction", "wallet", "loan"
    )
    private val credentialKeywords = listOf(
        "enter otp", "share otp", "confirm password", "password reset", "pin"
    )
    private val promotionKeywords = listOf(
        "sale", "discount", "cashback", "deal", "limited time", "offer", "promo", "buy now"
    )

    fun extract(normalizedText: String): SignalFeatures {
        return SignalFeatures(
            hasUrl = urlRegex.containsMatchIn(normalizedText),
            hasShortUrl = shortUrlRegex.containsMatchIn(normalizedText),
            hasActionVerb = actionVerbKeywords.any { normalizedText.contains(it) },
            hasUrgency = urgencyKeywords.any { normalizedText.contains(it) },
            hasFinancialKeyword = financialKeywords.any { normalizedText.contains(it) },
            hasCredentialRequest = credentialKeywords.any { normalizedText.contains(it) },
            isPromotion = promotionKeywords.any { normalizedText.contains(it) }
        )
    }
}

