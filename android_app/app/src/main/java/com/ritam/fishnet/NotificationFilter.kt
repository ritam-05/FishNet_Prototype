package com.ritam.fishnet

import java.util.Locale

object NotificationFilter {

    private const val MIN_TEXT_LENGTH = 8

    private val otpPhraseRegex = Regex(
        pattern = """\b(otp|verification code|one[\s-]*time password|use code|do not share)\b"""
    )
    private val otpCodeRegex = Regex(pattern = """(?<!\d)\d{4,8}(?!\d)""")
    private val otpBankFormatRegex = Regex(
        pattern = """\b(otp|verification code)\b.{0,40}(?<!\d)\d{4,8}(?!\d)"""
    )

    private val transactionKeywordRegex = Regex(
        pattern = """\b(debited|credited|txn(?:\s*id)?|upi|neft|imps|balance|a\/c|account)\b"""
    )
    private val currencyRegex = Regex(
        pattern = """(?:\u20B9|rs\.?|inr)\s?\d[\d,]*(?:\.\d{1,2})?"""
    )
    private val transactionIdRegex = Regex(
        pattern = """\b(?:txn(?:\s*id)?|utr|ref(?:erence)?)[:\s-]*[a-z0-9-]{6,}\b"""
    )

    private val deliveryRegex = Regex(
        pattern = """\b(order|shipment|delivered|out for delivery|tracking(?:\s*id)?|awb)\b"""
    )

    private val simCarrierRegex = Regex(
        pattern = """\b(recharge|validity|data pack|network|prepaid|postpaid|sim)\b"""
    )

    enum class DecisionReason {
        INVALID_PACKAGE,
        SHORT_OR_EMPTY_MESSAGE,
        OTP_STRUCTURED,
        TRANSACTION_STRUCTURED,
        DELIVERY_STRUCTURED,
        SIM_CARRIER_STRUCTURED,
        OTHER
    }

    data class FilterDecision(
        val isSystemSafe: Boolean,
        val reason: DecisionReason,
        val normalizedText: String,
        val normalizedPackage: String
    )

    fun evaluate(text: String?, packageName: String?): FilterDecision {
        val normalizedPackage = packageName?.trim()?.lowercase(Locale.ROOT).orEmpty()
        if (normalizedPackage.isBlank()) {
            return FilterDecision(
                isSystemSafe = true,
                reason = DecisionReason.INVALID_PACKAGE,
                normalizedText = "",
                normalizedPackage = normalizedPackage
            )
        }

        val normalizedText = text?.trim()?.lowercase(Locale.ROOT).orEmpty()
        if (normalizedText.length < MIN_TEXT_LENGTH) {
            return FilterDecision(
                isSystemSafe = true,
                reason = DecisionReason.SHORT_OR_EMPTY_MESSAGE,
                normalizedText = normalizedText,
                normalizedPackage = normalizedPackage
            )
        }

        val hasOtpSignal = isOtpStructuredMessage(normalizedText)
        if (hasOtpSignal) {
            return FilterDecision(
                isSystemSafe = true,
                reason = DecisionReason.OTP_STRUCTURED,
                normalizedText = normalizedText,
                normalizedPackage = normalizedPackage
            )
        }

        val hasTransactionSignal = isTransactionAlert(normalizedText)
        if (hasTransactionSignal) {
            return FilterDecision(
                isSystemSafe = true,
                reason = DecisionReason.TRANSACTION_STRUCTURED,
                normalizedText = normalizedText,
                normalizedPackage = normalizedPackage
            )
        }

        val hasDeliverySignal = deliveryRegex.containsMatchIn(normalizedText)
        if (hasDeliverySignal) {
            return FilterDecision(
                isSystemSafe = true,
                reason = DecisionReason.DELIVERY_STRUCTURED,
                normalizedText = normalizedText,
                normalizedPackage = normalizedPackage
            )
        }

        val hasSimCarrierSignal = simCarrierRegex.containsMatchIn(normalizedText)
        if (hasSimCarrierSignal) {
            return FilterDecision(
                isSystemSafe = true,
                reason = DecisionReason.SIM_CARRIER_STRUCTURED,
                normalizedText = normalizedText,
                normalizedPackage = normalizedPackage
            )
        }

        return FilterDecision(
            isSystemSafe = false,
            reason = DecisionReason.OTHER,
            normalizedText = normalizedText,
            normalizedPackage = normalizedPackage
        )
    }

    private fun isOtpStructuredMessage(text: String): Boolean {
        val hasOtpPhrase = otpPhraseRegex.containsMatchIn(text)
        val hasOtpCode = otpCodeRegex.containsMatchIn(text)
        return otpBankFormatRegex.containsMatchIn(text) || (hasOtpPhrase && hasOtpCode)
    }

    private fun isTransactionAlert(text: String): Boolean {
        val hasTransactionKeyword = transactionKeywordRegex.containsMatchIn(text)
        val hasCurrency = currencyRegex.containsMatchIn(text)
        val hasTransactionId = transactionIdRegex.containsMatchIn(text)
        return hasTransactionKeyword && (hasCurrency || hasTransactionId)
    }
}
