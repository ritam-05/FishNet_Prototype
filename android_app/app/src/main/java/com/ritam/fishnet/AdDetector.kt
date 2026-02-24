package com.ritam.fishnet

import java.util.Locale

object AdDetector {

    private val adKeywordRegex = Regex(
        pattern = """\b(%\s?off|cashback|limited time|buy now|sale|offer|discount|promo|deal)\b""",
        option = RegexOption.IGNORE_CASE
    )
    private val percentageDiscountRegex = Regex("""\b\d{1,2}%\s?off\b""", RegexOption.IGNORE_CASE)
    private val repeatedOfferRegex = Regex("""\boffer\b""", RegexOption.IGNORE_CASE)
    private val multiExclamationRegex = Regex("""!{2,}""")
    private val marketingToneRegex = Regex(
        """\b(shop now|hurry|don't miss|exclusive|grab now|limited stock|best price|today only)\b""",
        RegexOption.IGNORE_CASE
    )
    private val allCapsWordRegex = Regex("""\b[A-Z]{4,}\b""")

    fun isAd(text: String): Boolean {
        if (text.isBlank()) return false

        val normalized = text.lowercase(Locale.ROOT)
        var signals = 0

        if (adKeywordRegex.containsMatchIn(normalized)) signals++
        if (percentageDiscountRegex.containsMatchIn(normalized)) signals++
        if (marketingToneRegex.containsMatchIn(normalized)) signals++
        if (multiExclamationRegex.containsMatchIn(text)) signals++
        if (allCapsWordRegex.containsMatchIn(text)) signals++
        if (hasHeavyEmojiUsage(text)) signals++
        if (repeatedOfferRegex.findAll(normalized).count() >= 2) signals++

        return signals >= 2
    }

    private fun hasHeavyEmojiUsage(text: String): Boolean {
        val totalCodePoints = text.codePointCount(0, text.length).coerceAtLeast(1)
        val emojiCount = countEmojiCodePoints(text)
        val emojiDensity = emojiCount.toDouble() / totalCodePoints.toDouble()
        return emojiCount >= 3 || emojiDensity >= 0.08
    }

    private fun countEmojiCodePoints(text: String): Int {
        var count = 0
        var index = 0
        while (index < text.length) {
            val codePoint = text.codePointAt(index)
            if (isLikelyEmoji(codePoint)) {
                count++
            }
            index += Character.charCount(codePoint)
        }
        return count
    }

    private fun isLikelyEmoji(codePoint: Int): Boolean {
        return codePoint in 0x1F300..0x1FAFF || codePoint in 0x2600..0x27BF
    }
}
