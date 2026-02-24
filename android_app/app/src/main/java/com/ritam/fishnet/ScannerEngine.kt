package com.ritam.fishnet

import android.content.Context
import android.util.Log

object ScannerEngine {

    @Volatile
    private var classifier: PhishingClassifier? = null

    fun classifier(context: Context): PhishingClassifier {
        val existing = classifier
        if (existing != null) return existing

        return synchronized(this) {
            classifier ?: PhishingClassifier(context.applicationContext).also {
                classifier = it
            }
        }
    }

    fun tryClassifier(context: Context): PhishingClassifier? {
        return runCatching { classifier(context) }
            .onFailure { Log.e(TAG, "Classifier initialization failed.", it) }
            .getOrNull()
    }

    private const val TAG = "ScannerEngine"
}
