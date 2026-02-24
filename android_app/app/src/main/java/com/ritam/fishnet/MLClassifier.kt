package com.ritam.fishnet

import android.content.Context
import android.util.Log

class MLClassifier private constructor(context: Context) {

    private val classifier: PhishingClassifier? = ScannerEngine.tryClassifier(context.applicationContext)

    fun classify(text: String): MLClassification {
        val model = classifier
            ?: return MLClassification(
                isPhishing = false,
                phishingProbability = 0f,
                phishingSubtype = null
            )

        val modelResult = model.classify(text)
        val isPhishing = modelResult.finalClass != PhishingClassifier.SAFE_CLASS
        val phishingSubtype = if (isPhishing) {
            detectPhishingSubtype(text)
        } else {
            null
        }
        Log.d(TAG, "Model finalClass=${modelResult.finalClass}, isPhishing=$isPhishing")

        return MLClassification(
            isPhishing = isPhishing,
            phishingProbability = modelResult.confidence,
            phishingSubtype = phishingSubtype
        )
    }

    private fun detectPhishingSubtype(text: String): String {
        val normalized = text.lowercase()
        return when {
            normalized.contains("account suspended") || normalized.contains("verify now") -> {
                "Account Suspension Scam"
            }
            normalized.contains("reward") ||
                normalized.contains("won") ||
                normalized.contains("claim prize") -> {
                "Fake Reward Scam"
            }
            normalized.contains("update kyc") ||
                normalized.contains("pan") ||
                normalized.contains("aadhaar") -> {
                "KYC Fraud"
            }
            else -> "General Phishing"
        }
    }

    companion object {
        private const val TAG = "CLASSIFIER"

        @Volatile
        private var instance: MLClassifier? = null

        fun getInstance(context: Context): MLClassifier {
            val existing = instance
            if (existing != null) return existing

            return synchronized(this) {
                instance ?: MLClassifier(context).also { instance = it }
            }
        }
    }
}

data class MLClassification(
    val isPhishing: Boolean,
    val phishingProbability: Float,
    val phishingSubtype: String?
)
