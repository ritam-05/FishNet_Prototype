package com.ritam.fishnet.security.firewall

import com.ritam.fishnet.security.db.DomainProfile
import com.ritam.fishnet.security.db.DomainProfileDao
import java.net.URI
import kotlin.math.ln

class DomainReputationManager(
    private val domainDao: DomainProfileDao
) {
    private val urlRegex = Regex("""((?:https?://|www\.)[^\s]+)""")
    private val suspiciousTlds = setOf(".xyz", ".top", ".live", ".click", ".ru", ".tk", ".ml", ".ga", ".cf")
    private val shorteners = setOf("bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly")

    suspend fun analyze(text: String): DomainAnalysis {
        val domains = extractDomains(text)
        if (domains.isEmpty()) {
            return DomainAnalysis(
                domains = emptyList(),
                domainRisk = 0f,
                hasSuspiciousDomain = false,
                hasShortenedUrl = false
            )
        }

        var cumulativeRisk = 0f
        var suspiciousDetected = false
        var shortenerDetected = false
        domains.forEach { domain ->
            val heuristicRisk = heuristicRisk(domain)
            val historyRisk = domainDao.get(domain)?.averageRisk ?: 0f
            val blended = (0.65f * heuristicRisk) + (0.35f * historyRisk)
            cumulativeRisk += blended
            suspiciousDetected = suspiciousDetected || heuristicRisk >= 0.5f
            shortenerDetected = shortenerDetected || shorteners.contains(domain)
        }

        return DomainAnalysis(
            domains = domains,
            domainRisk = (cumulativeRisk / domains.size).coerceIn(0f, 1f),
            hasSuspiciousDomain = suspiciousDetected,
            hasShortenedUrl = shortenerDetected
        )
    }

    suspend fun updateReputation(domains: List<String>, risk: Float, flagged: Boolean) {
        domains.forEach { domain ->
            val current = domainDao.get(domain)
            val next = if (current == null) {
                DomainProfile(
                    domain = domain,
                    timesSeen = 1,
                    averageRisk = risk.coerceIn(0f, 1f),
                    flaggedCount = if (flagged) 1 else 0
                )
            } else {
                val times = current.timesSeen + 1
                val avg = ((current.averageRisk * current.timesSeen) + risk) / times
                current.copy(
                    timesSeen = times,
                    averageRisk = avg.coerceIn(0f, 1f),
                    flaggedCount = current.flaggedCount + if (flagged) 1 else 0
                )
            }
            domainDao.insert(next)
        }
    }

    private fun extractDomains(text: String): List<String> {
        val matches = urlRegex.findAll(text)
            .mapNotNull { parseDomain(it.value) }
            .map { it.lowercase() }
            .distinct()
            .toList()
        return matches
    }

    private fun parseDomain(url: String): String? {
        return runCatching {
            val normalized = if (url.startsWith("http")) url else "https://$url"
            URI(normalized).host?.removePrefix("www.")
        }.getOrNull()
    }

    private fun heuristicRisk(domain: String): Float {
        var risk = 0f
        if (suspiciousTlds.any { domain.endsWith(it) }) risk += 0.45f
        if (shorteners.contains(domain)) risk += 0.40f
        if (hasHighEntropy(domain)) risk += 0.20f
        if (hasDigitSubstitutionPattern(domain)) risk += 0.25f
        return risk.coerceIn(0f, 1f)
    }

    private fun hasHighEntropy(domain: String): Boolean {
        val label = domain.substringBefore(".")
        if (label.length < 8) return false
        val freq = label.groupingBy { it }.eachCount()
        val entropy = freq.values.fold(0.0) { acc, count ->
            val p = count.toDouble() / label.length.toDouble()
            acc - p * (ln(p) / ln(2.0))
        }
        return entropy >= 3.8
    }

    private fun hasDigitSubstitutionPattern(domain: String): Boolean {
        val label = domain.substringBefore(".")
        val hasLetters = label.any(Char::isLetter)
        val hasDigits = label.any(Char::isDigit)
        if (!hasLetters || !hasDigits) return false

        val normalized = label
            .replace('0', 'o')
            .replace('1', 'l')
            .replace('3', 'e')
            .replace('4', 'a')
            .replace('5', 's')
            .replace('7', 't')
        return listOf("amazon", "google", "paytm", "phonepe", "bank").any { normalized.contains(it) }
    }
}

