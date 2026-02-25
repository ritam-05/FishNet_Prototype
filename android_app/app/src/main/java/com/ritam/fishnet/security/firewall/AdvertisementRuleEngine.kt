package com.ritam.fishnet.security.firewall

import java.util.Locale

data class AdDetectionResult(
    val isAdvertisement: Boolean,
    val hasPromoSignals: Boolean,
    val excludedByPhishingSignals: Boolean,
    val matchedSignals: List<String>
)

data class AdLabelExplanation(
    val title: String,
    val reasons: List<String>
)

class AdExplanationManager {
    fun toReasonString(result: AdDetectionResult): String {
        if (!result.isAdvertisement) return "No advertisement signal"
        if (result.matchedSignals.isEmpty()) return "Advertisement rule match"
        return "Advertisement rule match: ${result.matchedSignals.joinToString(", ")}"
    }

    fun toUiExplanation(result: AdDetectionResult): AdLabelExplanation {
        return AdLabelExplanation(
            title = "Promotional notification detected",
            reasons = if (result.matchedSignals.isNotEmpty()) {
                result.matchedSignals
            } else {
                listOf("Commercial intent detected")
            }
        )
    }
}

class AdvertisementRuleEngine {

    // Commercial/promo words are intentionally broad to catch unknown and new brands.
    private val promoKeywords = listOf(
        "sale", "discount", "off", "flat off", "limited time", "today only", "ending soon",
        "expiry", "last chance", "cashback", "bonus", "reward", "coupon", "code", "promo code",
        "offer", "free shipping", "free trial", "buy one get one", "bogo", "flash sale",
        "mega sale", "weekend sale", "seasonal sale", "festival offer", "member price",
        "recharge offer", "top-up offer", "referral bonus", "invite bonus", "loyalty points",
        "new launch", "hot deal", "trending now", "viral offer", "special price", "price drop",
        "best price", "lowest price", "shop now", "buy now", "redeem"
    )

    // Patterns cover common ad templates (% off, urgency sale copy, BOGO variants, coupon pushes).
    private val promoPatterns = listOf(
        Regex("""\b\d{1,3}\s?%\s?off\b"""),
        Regex("""\bflat\s?\d{1,3}\s?%?\s?off\b"""),
        Regex("""\b(today only|limited time|ending soon|last chance|expires?\s?(soon|today)?)\b"""),
        Regex("""\b(bogo|buy\s*1\s*get\s*1|buy one get one)\b"""),
        Regex("""\b(free shipping|free trial|promo code|coupon code)\b"""),
        Regex("""\b(flash sale|mega sale|weekend sale|seasonal sale|festival offer)\b"""),
        Regex("""\b(new launch|hot deal|trending now|viral offer|special price|price drop|best price|lowest price)\b""")
    )

    private val urlRegex = Regex("""(https?://|www\.)\S+""")
    private val urlTokenRegex = Regex("""[a-z0-9]+""")
    private val commercialUrlTokens = setOf(
        "shop", "buy", "deal", "offer", "promo", "discount", "coupon", "save", "sale", "store", "cart", "checkout"
    )

    private val promoEmojis = listOf("🛍", "🔥", "💰", "🏷", "🎉", "🎁")
    private val priceRegex = Regex("""(\$|₹|rs\.?|inr)\s?\d{1,7}|\b\d{2,7}\s?(usd|inr)\b|\b\d{2,7}\s?only\b""")
    private val shortUrlRegex = Regex("""\b(bit\.ly|tinyurl|goo\.gl|t\.co|cutt\.ly|shorturl|rebrand\.ly)\b""")
    private val appPromoKeywords = listOf(
        "premium", "upgrade now", "try premium", "subscribe now", "ad-free", "unlock now",
        "deal of the day", "great indian festival", "big billion days", "special picks",
        "recommended for you", "wishlist", "cart waiting", "price dropped in your cart",
        "supercoin", "plus zone", "prime day", "lightning deal"
    )
    private val commercePushKeywords = listOf(
        "offer", "sale", "deal", "discount", "cashback", "price drop", "price dropped",
        "wishlist", "cart", "shop now", "buy now", "festival", "coupon", "voucher",
        "limited time", "ending soon", "today only", "special price"
    )
    private val knownPromoHeavyApps = listOf(
        "com.flipkart.android",
        "com.amazon.mshop.android.shopping",
        "in.amazon.mshop.android.shopping",
        "com.myntra.android",
        "com.meesho.supply",
        "com.snapdeal.main",
        "com.ril.ajio",
        "com.shopclues",
        "com.tatacliq",
        "com.nykaa",
        "com.spotify.music"
    )

    private val phishingActionKeywords = listOf(
        "click", "verify", "login", "confirm", "update", "reset", "submit", "authenticate", "unlock"
    )
    private val phishingUrgencyKeywords = listOf(
        "urgent", "immediately", "suspended", "blocked", "last warning", "act now", "account locked"
    )
    private val phishingCredentialKeywords = listOf(
        "enter otp", "share otp", "confirm password", "password reset", "cvv", "pin", "mpin", "netbanking",
        "bank details", "card details", "verify identity", "kyc update", "submit pan", "aadhaar"
    )
    private val phishingSensitiveKeywords = listOf(
        "bank", "account", "payment", "transaction", "wallet", "upi", "pan", "aadhaar", "ssn", "identity"
    )

    // Suspicious domain heuristics are conservative and only used for phishing exclusion checks.
    private val suspiciousDomainTlds = setOf("ru", "tk", "ml", "ga", "cf", "gq", "zip", "click", "top", "work")
    private val ipHostRegex = Regex("""\b\d{1,3}(\.\d{1,3}){3}\b""")

    fun isAdvertisementNotification(text: String, packageName: String): Boolean {
        return analyze(text = text, packageName = packageName).isAdvertisement
    }

    fun analyze(
        text: String,
        packageName: String,
        hasCredentialRequestSignal: Boolean = false,
        hasUrgencySignal: Boolean = false,
        hasActionSignal: Boolean = false,
        hasFinancialSignal: Boolean = false,
        suspiciousUrlSignal: Boolean = false
    ): AdDetectionResult {
        val normalizedText = text.lowercase(Locale.ROOT)
        val urls = urlRegex.findAll(normalizedText).map { it.value }.toList()
        val matchedSignals = mutableListOf<String>()

        val keywordMatches = promoKeywords.filter { normalizedText.contains(it) }
        if (keywordMatches.isNotEmpty()) {
            matchedSignals += "promo_keywords(${keywordMatches.take(4).joinToString(",")})"
        }

        if (promoPatterns.any { it.containsMatchIn(normalizedText) }) {
            matchedSignals += "promo_template_pattern"
        }

        val hasCommercialUrl = urls.any { url ->
            val tokens = urlTokenRegex.findAll(url).map { it.value }.toSet()
            tokens.any { it in commercialUrlTokens }
        }
        if (hasCommercialUrl) {
            matchedSignals += "commercial_url_token"
        }

        val promoEmojiCount = promoEmojis.count { normalizedText.contains(it) }
        if (promoEmojiCount >= 2) {
            matchedSignals += "promo_emoji_format"
        }

        val shortTextWithPriceAndPush = normalizedText.length <= 120 &&
            priceRegex.containsMatchIn(normalizedText) &&
            (hasCommercialUrl || containsAny(normalizedText, listOf("shop", "buy", "redeem", "order now", "claim offer")))
        if (shortTextWithPriceAndPush) {
            matchedSignals += "short_price_push"
        }

        val normalizedPackage = packageName.lowercase(Locale.ROOT)
        val packageHint = normalizedPackage.let { pkg ->
            pkg.contains("shop") || pkg.contains("store") || pkg.contains("deal") || pkg.contains("mall")
        }
        if (packageHint && matchedSignals.isNotEmpty()) {
            matchedSignals += "commerce_package_hint"
        }

        val isKnownPromoApp = knownPromoHeavyApps.any { normalizedPackage == it || normalizedPackage.startsWith("$it.") }
        val hasAppPromoCopy = containsAny(normalizedText, appPromoKeywords)
        val hasCommercePushCopy = containsAny(normalizedText, commercePushKeywords)
        if (isKnownPromoApp && (matchedSignals.isNotEmpty() || hasAppPromoCopy)) {
            matchedSignals += "known_promo_app_signal"
        } else if (isKnownPromoApp && hasCommercePushCopy) {
            matchedSignals += "known_app_commerce_push_signal"
        } else if (hasAppPromoCopy && packageHint) {
            matchedSignals += "package_promo_copy_signal"
        }

        val hasPromoSignals = matchedSignals.isNotEmpty()
        if (!hasPromoSignals) {
            return AdDetectionResult(
                isAdvertisement = false,
                hasPromoSignals = false,
                excludedByPhishingSignals = false,
                matchedSignals = emptyList()
            )
        }

        val hasSuspiciousDomain = suspiciousUrlSignal || urls.any { isSuspiciousDomain(it) }
        val hasCredentialSignals = hasCredentialRequestSignal || containsAny(normalizedText, phishingCredentialKeywords)
        val hasUrgencySignals = hasUrgencySignal || containsAny(normalizedText, phishingUrgencyKeywords)
        val hasActionSignals = hasActionSignal || containsAny(normalizedText, phishingActionKeywords)
        val hasSensitiveSignals = hasFinancialSignal || containsAny(normalizedText, phishingSensitiveKeywords)

        val explicitPhishingSignals =
            (hasCredentialSignals && (hasActionSignals || hasSuspiciousDomain || hasUrgencySignals)) ||
                (hasSuspiciousDomain && hasUrgencySignals && hasActionSignals && hasSensitiveSignals)

        return AdDetectionResult(
            isAdvertisement = hasPromoSignals && !explicitPhishingSignals,
            hasPromoSignals = hasPromoSignals,
            excludedByPhishingSignals = explicitPhishingSignals,
            matchedSignals = matchedSignals
        )
    }

    private fun containsAny(text: String, patterns: List<String>): Boolean {
        return patterns.any { text.contains(it) }
    }

    private fun isSuspiciousDomain(url: String): Boolean {
        val host = url
            .substringAfter("://", url)
            .substringAfter("www.")
            .substringBefore("/")
            .substringBefore("?")
            .trim()
        if (host.isBlank()) return false
        if (host.contains("xn--")) return true
        if (ipHostRegex.containsMatchIn(host)) return true
        val tld = host.substringAfterLast(".", "")
        return tld in suspiciousDomainTlds
    }
}
