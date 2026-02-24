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
}
