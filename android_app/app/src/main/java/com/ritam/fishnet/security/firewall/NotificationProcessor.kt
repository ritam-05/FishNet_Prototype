package com.ritam.fishnet.security.firewall

import android.content.Context
import android.util.Log
import com.ritam.fishnet.AppSettings
import com.ritam.fishnet.ClassificationType
import com.ritam.fishnet.MLClassifier
import com.ritam.fishnet.UserFeedbackRepository
import com.ritam.fishnet.security.AppTier
import com.ritam.fishnet.security.NotificationIntentType
import com.ritam.fishnet.security.db.FishNetSecurityDatabase
import java.util.ArrayDeque

class NotificationProcessor private constructor(
    private val appContext: Context,
    private val mlClassifier: MLClassifier,
    private val appTierResolver: AppTierResolver,
    private val intentDetector: IntentDetector,
    private val signalExtractor: SignalExtractor,
    private val domainReputationManager: DomainReputationManager,
    private val advertisementRuleEngine: AdvertisementRuleEngine,
    private val adExplanationManager: AdExplanationManager,
    private val scamDetector: ScamDetector,
    private val emailThreatEngine: EmailThreatEngine,
    private val rareAppManager: RareAppManager,
    private val riskEngine: RiskEngine
) {
    private val recentAppTimestamps = HashMap<String, ArrayDeque<Long>>()
    private val recentAppMessages = HashMap<String, ArrayDeque<Int>>()
    private val spamLock = Any()

    suspend fun processNotification(
        notificationId: String,
        text: String,
        packageName: String,
        timestamp: Long
    ): SecurityDecision {
        val normalizedText = text.lowercase()
        val tier = appTierResolver.resolve(packageName)
        val intent = intentDetector.detectIntentType(normalizedText)
        val signals = signalExtractor.extract(normalizedText)
        val domainAnalysis = domainReputationManager.analyze(normalizedText)
        val suspiciousUrl = signals.hasUrl &&
            (domainAnalysis.hasSuspiciousDomain || signals.hasShortUrl || domainAnalysis.hasShortenedUrl)

        // 1) Hard safe filter.
        if (isHardSafeIntent(intent)) {
            val finalized = finalizeDecision(
                packageName = packageName,
                timestamp = timestamp,
                decision = baseDecision(
                    label = SecurityLabel.SAFE_USEFUL,
                    subtype = null,
                    tier = tier,
                    intent = intent,
                    mlScore = 0f,
                    finalRisk = 0f,
                    phishingSignals = 0,
                    spamSignals = 0,
                    reason = "Hard safe intent short-circuit"
                )
            )
            return applyFeedbackOverrideIfPresent(notificationId, finalized)
        }

        // 2) Dedicated email intelligence layer runs before ML.
        val emailDecision = if (tier == AppTier.EMAIL || emailThreatEngine.isEmailApp(packageName)) {
            emailThreatEngine.evaluate(
                text = normalizedText,
                packageName = packageName,
                signals = signals,
                domain = domainAnalysis
            )
        } else {
            EmailThreatDecision(
                resolved = false,
                label = null,
                subtype = null,
                riskBoost = 0f,
                reason = "Not email path"
            )
        }
        if (emailDecision.resolved && emailDecision.label != null) {
            val finalized = finalizeDecision(
                packageName = packageName,
                timestamp = timestamp,
                decision = baseDecision(
                    label = emailDecision.label,
                    subtype = emailDecision.subtype,
                    tier = tier,
                    intent = intent,
                    mlScore = 0f,
                    finalRisk = emailDecision.riskBoost.coerceIn(0f, 1f),
                    phishingSignals = 0,
                    spamSignals = if (emailDecision.label == SecurityLabel.IRRELEVANT_AD) 1 else 0,
                    reason = emailDecision.reason
                )
            )
            return applyFeedbackOverrideIfPresent(notificationId, finalized)
        }

        // 3) Rare app suppression check.
        val rareState = rareAppManager.recordNotification(packageName)
        val lowPriorityHint = rareState.isLowPriority

        // 4) Ad detector.
        val adDetection = advertisementRuleEngine.analyze(
            text = text,
            packageName = packageName,
            hasCredentialRequestSignal = signals.hasCredentialRequest,
            hasUrgencySignal = signals.hasUrgency,
            hasActionSignal = signals.hasActionVerb,
            hasFinancialSignal = signals.hasFinancialKeyword,
            suspiciousUrlSignal = suspiciousUrl
        )
        if (adDetection.isAdvertisement) {
            val explanation = adExplanationManager.toUiExplanation(adDetection)
            val finalized = finalizeDecision(
                packageName = packageName,
                timestamp = timestamp,
                decision = baseDecision(
                    label = SecurityLabel.IRRELEVANT_AD,
                    subtype = null,
                    tier = tier,
                    intent = intent,
                    mlScore = 0f,
                    finalRisk = 0f,
                    phishingSignals = 0,
                    spamSignals = 1,
                    reason = adExplanationManager.toReasonString(adDetection),
                    adSignals = explanation.reasons,
                    lowPriorityBucket = lowPriorityHint
                )
            )
            return applyFeedbackOverrideIfPresent(notificationId, finalized)
        }

        // 5) Spam detector.
        val fraudIndicators = signals.hasCredentialRequest ||
            signals.hasActionVerb ||
            signals.hasUrgency ||
            suspiciousUrl ||
            signals.hasFinancialKeyword
        val isSpam = isHighFrequency(packageName, timestamp) || isRepeatedSimilarContent(packageName, normalizedText)
        if (isSpam && !fraudIndicators) {
            val finalized = finalizeDecision(
                packageName = packageName,
                timestamp = timestamp,
                decision = baseDecision(
                    label = SecurityLabel.SPAM,
                    subtype = null,
                    tier = tier,
                    intent = intent,
                    mlScore = 0f,
                    finalRisk = 0f,
                    phishingSignals = 0,
                    spamSignals = 1,
                    reason = "High-frequency/repeated content without fraud indicators",
                    lowPriorityBucket = lowPriorityHint
                )
            )
            return applyFeedbackOverrideIfPresent(notificationId, finalized)
        }

        // 6) Lightweight scam detector.
        val scamResult = scamDetector.detect(normalizedText, signals, suspiciousUrl)
        if (scamResult.isScam) {
            val finalized = finalizeDecision(
                packageName = packageName,
                timestamp = timestamp,
                decision = baseDecision(
                    label = SecurityLabel.SCAM,
                    subtype = scamResult.subtype,
                    tier = tier,
                    intent = intent,
                    mlScore = 0f,
                    finalRisk = 0.62f,
                    phishingSignals = 0,
                    spamSignals = 0,
                    reason = scamResult.reason,
                    lowPriorityBucket = lowPriorityHint
                )
            )
            return applyFeedbackOverrideIfPresent(notificationId, finalized)
        }

        // 7) Multi-signal risk engine (ML + domain memory + behavioral memory).
        val phishingSignals = phishingSignals(tier, signals)
        val hasCredentialKeywords = signals.hasCredentialRequest || containsCredentialKeyword(normalizedText)
        val hasAction = signals.hasActionVerb
        val hasRouteSignal = suspiciousUrl || signals.hasUrl || signals.hasUrgency
        val rawMlScore = mlClassifier.classify(text).phishingProbability.coerceIn(0f, 1f)
        val weightedMlScore = rawMlScore

        val riskBoost = emailDecision.riskBoost
        var finalRisk = riskEngine.computeFinalRisk(
            mlScore = weightedMlScore,
            phishingSignals = phishingSignals,
            anomalyScore = if (isSpam) 0.7f else 0.2f,
            domainRisk = domainAnalysis.domainRisk,
            tier = tier
        ) + riskBoost
        val primaryDomain = domainAnalysis.domains.firstOrNull()
        finalRisk += UserFeedbackRepository.domainRiskAdjustment(primaryDomain)
        val appRiskAdjustment = UserFeedbackRepository.appRiskAdjustment(packageName)
        val mlContribution = 0.4f * weightedMlScore
        finalRisk += (mlContribution * appRiskAdjustment)
        if (lowPriorityHint) {
            finalRisk *= 0.85f
        }
        finalRisk = finalRisk.coerceIn(0f, 1f)

        val threshold = fixedThresholdFor(tier)
        val isPhishing = hasCredentialKeywords &&
            hasAction &&
            hasRouteSignal &&
            phishingSignals >= 2 &&
            finalRisk >= threshold &&
            tier != AppTier.SYSTEM &&
            tier != AppTier.MEDIA

        if (isPhishing) {
            val subtype = detectPhishingSubtype(normalizedText, tier, finalRisk)
            val decision = baseDecision(
                label = SecurityLabel.PHISHING,
                subtype = subtype,
                tier = tier,
                intent = intent,
                mlScore = weightedMlScore,
                finalRisk = finalRisk,
                phishingSignals = phishingSignals,
                spamSignals = 0,
                reason = "Strict phishing conditions satisfied",
                lowPriorityBucket = false
            )
            domainReputationManager.updateReputation(
                domains = domainAnalysis.domains,
                risk = decision.finalRisk,
                flagged = true
            )
            val finalized = finalizeDecision(packageName = packageName, timestamp = timestamp, decision = decision)
            return applyFeedbackOverrideIfPresent(notificationId, finalized)
        }

        val safeDecision = baseDecision(
            label = SecurityLabel.SAFE_USEFUL,
            subtype = null,
            tier = tier,
            intent = intent,
            mlScore = weightedMlScore,
            finalRisk = finalRisk,
            phishingSignals = phishingSignals,
            spamSignals = 0,
            reason = "Default safe fallback",
            lowPriorityBucket = lowPriorityHint
        )
        domainReputationManager.updateReputation(
            domains = domainAnalysis.domains,
            risk = safeDecision.finalRisk,
            flagged = domainAnalysis.hasSuspiciousDomain
        )
        val finalized = finalizeDecision(packageName = packageName, timestamp = timestamp, decision = safeDecision)
        return applyFeedbackOverrideIfPresent(notificationId, finalized)
    }

    private suspend fun applyFeedbackOverrideIfPresent(
        notificationId: String,
        decision: SecurityDecision
    ): SecurityDecision {
        val override = UserFeedbackRepository.feedbackOverride(notificationId) ?: return decision
        val label = when (override) {
            ClassificationType.SAFE_USEFUL -> SecurityLabel.SAFE_USEFUL
            ClassificationType.PHISHING -> SecurityLabel.PHISHING
            ClassificationType.SCAM -> SecurityLabel.SCAM
            ClassificationType.IRRELEVANT_AD -> SecurityLabel.IRRELEVANT_AD
            ClassificationType.SPAM -> SecurityLabel.SPAM
        }
        val subtype = when (label) {
            SecurityLabel.PHISHING -> {
                if (decision.finalRisk > PHISHING_SUBTYPE_MIN_RISK) {
                    decision.threatSubtype ?: "PHISHING_GENERAL"
                } else {
                    null
                }
            }
            SecurityLabel.SCAM -> decision.threatSubtype ?: "SCAM_GENERAL"
            SecurityLabel.SPAM -> "Spam"
            else -> null
        }
        return decision.copy(
            label = label,
            threatSubtype = subtype,
            reason = "User feedback override applied"
        )
    }

    private suspend fun finalizeDecision(
        packageName: String,
        timestamp: Long,
        decision: SecurityDecision
    ): SecurityDecision {
        if (decision.label == SecurityLabel.SAFE_USEFUL) {
            rareAppManager.recordLikelyOpen(packageName, timestamp)
        }
        val isLowPriority = rareAppManager.evaluateSuppression(packageName, decision.label)
        if (decision.label == SecurityLabel.PHISHING || decision.label == SecurityLabel.SCAM) {
            return decision.copy(lowPriorityBucket = false)
        }
        return decision.copy(lowPriorityBucket = decision.lowPriorityBucket || isLowPriority)
    }

    private fun containsCredentialKeyword(normalizedText: String): Boolean {
        val keywords = listOf(
            "login",
            "verify account",
            "update kyc",
            "confirm password",
            "submit pan",
            "aadhaar",
            "bank details",
            "otp share",
            "account suspended",
            "unusual activity"
        )
        return keywords.any { normalizedText.contains(it) }
    }

    private fun isHardSafeIntent(intent: NotificationIntentType): Boolean {
        return intent == NotificationIntentType.SOCIAL_INTERACTION ||
            intent == NotificationIntentType.SYSTEM_STATUS ||
            intent == NotificationIntentType.MEDIA_PLAYBACK ||
            intent == NotificationIntentType.DELIVERY_UPDATE ||
            intent == NotificationIntentType.CALENDAR_REMINDER ||
            intent == NotificationIntentType.VERIFIED_BANK_TRANSACTION ||
            intent == NotificationIntentType.TRANSACTION_RECEIPT ||
            intent == NotificationIntentType.SPORTS_UPDATE ||
            intent == NotificationIntentType.SOCIAL_BIRTHDAY ||
            intent == NotificationIntentType.SOCIAL_REACTION ||
            intent == NotificationIntentType.APP_STATUS_UPDATE
    }

    private fun phishingSignals(tier: AppTier, signals: SignalFeatures): Int {
        var count = 0
        if (signals.hasUrl) count++
        if (signals.hasActionVerb) count++
        if (signals.hasFinancialKeyword) count++
        if (signals.hasUrgency) count++
        if (tier == AppTier.UNKNOWN) count++
        return count
    }

    private fun fixedThresholdFor(tier: AppTier): Float {
        return if (tier == AppTier.EMAIL) 0.75f else 0.70f
    }

    private fun detectPhishingSubtype(normalizedText: String, tier: AppTier, finalRisk: Float): String? {
        if (finalRisk <= PHISHING_SUBTYPE_MIN_RISK) return null
        if (tier == AppTier.EMAIL) {
            if (normalizedText.contains("login") || normalizedText.contains("verify account")) {
                return "PHISHING_EMAIL_LOGIN"
            }
            if (normalizedText.contains("payment") || normalizedText.contains("bank details")) {
                return "PHISHING_EMAIL_PAYMENT"
            }
            if (normalizedText.contains("kyc") || normalizedText.contains("pan") || normalizedText.contains("aadhaar")) {
                return "PHISHING_EMAIL_KYC"
            }
            return "PHISHING_EMAIL_LOGIN"
        }
        return "PHISHING_GENERAL"
    }

    private fun isHighFrequency(packageName: String, timestamp: Long): Boolean {
        synchronized(spamLock) {
            val queue = recentAppTimestamps.getOrPut(packageName) { ArrayDeque() }
            queue.addLast(timestamp)
            val windowMs = 5 * 60 * 1000L
            while (queue.isNotEmpty() && timestamp - queue.first() > windowMs) {
                queue.removeFirst()
            }
            return queue.size >= 8
        }
    }

    private fun isRepeatedSimilarContent(packageName: String, normalizedText: String): Boolean {
        synchronized(spamLock) {
            val queue = recentAppMessages.getOrPut(packageName) { ArrayDeque() }
            val sig = normalizedText
                .replace(Regex("""\d+"""), "#")
                .replace(Regex("""\s+"""), " ")
                .trim()
                .hashCode()
            queue.addLast(sig)
            while (queue.size > 20) queue.removeFirst()
            return queue.count { it == sig } >= 4
        }
    }

    private fun baseDecision(
        label: SecurityLabel,
        subtype: String?,
        tier: AppTier,
        intent: NotificationIntentType,
        mlScore: Float,
        finalRisk: Float,
        phishingSignals: Int,
        spamSignals: Int,
        reason: String,
        adSignals: List<String> = emptyList(),
        lowPriorityBucket: Boolean = false
    ): SecurityDecision {
        val risk = finalRisk.coerceIn(0f, 1f)
        return SecurityDecision(
            label = label,
            threatSubtype = subtype,
            finalRisk = risk,
            mlScore = mlScore.coerceIn(0f, 1f),
            phishingSignals = phishingSignals,
            spamSignals = spamSignals,
            tier = tier,
            intent = intent,
            riskMeter = riskEngine.riskMeter(risk),
            shouldBlock = risk >= 0.90f && AppSettings.isBlockingEnabled(appContext),
            promptProtectedMode = label == SecurityLabel.PHISHING && risk >= 0.70f,
            lowPriorityBucket = lowPriorityBucket,
            reason = reason,
            adSignals = adSignals
        )
    }

    companion object {
        @Volatile
        private var instance: NotificationProcessor? = null

        fun getInstance(context: Context): NotificationProcessor {
            val existing = instance
            if (existing != null) return existing
            return synchronized(this) {
                instance ?: create(context.applicationContext).also { instance = it }
            }
        }

        private fun create(context: Context): NotificationProcessor {
            val db = runCatching { FishNetSecurityDatabase.getInstance(context) }
                .onFailure { Log.e(TAG, "Room unavailable for processor. Using in-memory fallback.", it) }
                .getOrNull()
            val fallback = InMemorySecurityStore()
            val mlClassifier = MLClassifier.getInstance(context)
            return NotificationProcessor(
                appContext = context,
                mlClassifier = mlClassifier,
                appTierResolver = AppTierResolver(),
                intentDetector = IntentDetector(),
                signalExtractor = SignalExtractor(),
                domainReputationManager = DomainReputationManager(
                    db?.domainProfileDao() ?: fallback.domainDao
                ),
                advertisementRuleEngine = AdvertisementRuleEngine(),
                adExplanationManager = AdExplanationManager(),
                scamDetector = ScamDetector(),
                emailThreatEngine = EmailThreatEngine(),
                rareAppManager = RareAppManager(
                    appContext = context,
                    appUsageStatsDao = db?.appUsageStatsDao() ?: fallback.appUsageStatsDao
                ),
                riskEngine = RiskEngine()
            )
        }

        private const val TAG = "NotificationProcessor"
        private const val PHISHING_SUBTYPE_MIN_RISK = 0.50f
    }
}
