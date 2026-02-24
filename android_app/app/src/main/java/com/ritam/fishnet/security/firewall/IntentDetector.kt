package com.ritam.fishnet.security.firewall

import com.ritam.fishnet.security.NotificationIntentType

class IntentDetector {
    private val socialKeywords = listOf(
        "reacted", "liked", "commented", "shared", "birthday",
        "tagged", "mentioned", "friend request"
    )
    private val socialBirthdayKeywords = listOf("birthday", "wish")
    private val socialReactionKeywords = listOf("reacted", "liked", "commented", "mentioned")
    private val systemKeywords = listOf(
        "charging", "usb", "battery", "wifi", "bluetooth", "app updated", "sync complete"
    )
    private val mediaKeywords = listOf(
        "now playing", "paused", "next track"
    )
    private val calendarKeywords = listOf(
        "meeting", "calendar", "event", "reminder", "scheduled"
    )
    private val deliveryKeywords = listOf(
        "out for delivery", "delivered", "shipment", "tracking", "awb", "order arrived"
    )
    private val verifiedBankKeywords = listOf(
        "debited", "credited", "available balance", "transaction successful"
    )
    private val receiptKeywords = listOf(
        "receipt", "invoice", "order confirmation", "payment receipt"
    )
    private val sportsKeywords = listOf(
        "match", "score", "goal", "innings", "sports update", "live score"
    )
    private val financialKeywords = listOf(
        "debited", "credited", "upi", "rs.", "inr", "txn", "transaction"
    )
    private val promoKeywords = listOf(
        "sale", "discount", "cashback", "deal", "limited time", "offer", "promo"
    )

    fun detectIntentType(normalizedText: String): NotificationIntentType {
        return when {
            socialBirthdayKeywords.any { normalizedText.contains(it) } -> NotificationIntentType.SOCIAL_BIRTHDAY
            socialReactionKeywords.any { normalizedText.contains(it) } -> NotificationIntentType.SOCIAL_REACTION
            socialKeywords.any { normalizedText.contains(it) } -> NotificationIntentType.SOCIAL_INTERACTION
            deliveryKeywords.any { normalizedText.contains(it) } -> NotificationIntentType.DELIVERY_UPDATE
            calendarKeywords.any { normalizedText.contains(it) } -> NotificationIntentType.CALENDAR_REMINDER
            verifiedBankKeywords.any { normalizedText.contains(it) } -> NotificationIntentType.VERIFIED_BANK_TRANSACTION
            receiptKeywords.any { normalizedText.contains(it) } -> NotificationIntentType.TRANSACTION_RECEIPT
            sportsKeywords.any { normalizedText.contains(it) } -> NotificationIntentType.SPORTS_UPDATE
            normalizedText.contains("status") || normalizedText.contains("updated successfully") -> {
                NotificationIntentType.APP_STATUS_UPDATE
            }
            systemKeywords.any { normalizedText.contains(it) } -> NotificationIntentType.SYSTEM_STATUS
            mediaKeywords.any { normalizedText.contains(it) } -> NotificationIntentType.MEDIA_PLAYBACK
            calendarKeywords.any { normalizedText.contains(it) } -> NotificationIntentType.EVENT_REMINDER
            financialKeywords.any { normalizedText.contains(it) } -> NotificationIntentType.FINANCIAL_TRANSACTION
            promoKeywords.any { normalizedText.contains(it) } -> NotificationIntentType.PROMOTION
            else -> NotificationIntentType.UNKNOWN
        }
    }
}
