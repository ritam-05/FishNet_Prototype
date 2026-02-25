package com.ritam.fishnet.security.firewall

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AdvertisementRuleEngineTest {

    private val engine = AdvertisementRuleEngine()

    @Test
    fun detectsPromoByKeywordsAndCommercialUrl() {
        val text = "Flash sale today only! 70% off on all items. Shop now: https://example.com/deals"
        assertTrue(engine.isAdvertisementNotification(text, "com.newbrand.app"))
    }

    @Test
    fun detectsShortPricePushWithEmojiFormat() {
        val text = "🔥🎉 Rs 499 only, buy now https://shop.example.com"
        assertTrue(engine.isAdvertisementNotification(text, "com.trending.brand"))
    }

    @Test
    fun excludesWhenExplicitPhishingSignalsExist() {
        val result = engine.analyze(
            text = "Limited time offer! Verify account now at http://xn--paytm-secure.top and submit card details",
            packageName = "com.unknown.app",
            hasCredentialRequestSignal = true,
            hasUrgencySignal = true,
            hasActionSignal = true,
            hasFinancialSignal = true,
            suspiciousUrlSignal = true
        )
        assertFalse(result.isAdvertisement)
        assertTrue(result.excludedByPhishingSignals)
    }

    @Test
    fun detectsKnownShoppingAppPromotions() {
        val result = engine.analyze(
            text = "Big Billion Days deal of the day is live. Add to cart now.",
            packageName = "com.flipkart.android"
        )
        assertTrue(result.isAdvertisement)
    }

    @Test
    fun detectsSpotifyUpgradePromotions() {
        val result = engine.analyze(
            text = "Try Premium now for ad-free music. Upgrade now.",
            packageName = "com.spotify.music"
        )
        assertTrue(result.isAdvertisement)
    }

    @Test
    fun detectsAmazonCartAndWishlistPromotions() {
        val result = engine.analyze(
            text = "Price dropped in your cart. Limited time offer, shop now.",
            packageName = "in.amazon.mshop.android.shopping"
        )
        assertTrue(result.isAdvertisement)
    }
}
