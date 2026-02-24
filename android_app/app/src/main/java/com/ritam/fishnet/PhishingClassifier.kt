package com.ritam.fishnet

import ai.onnxruntime.OnnxJavaType
import ai.onnxruntime.OnnxTensor
import ai.onnxruntime.OrtEnvironment
import ai.onnxruntime.OrtSession
import ai.onnxruntime.TensorInfo
import android.content.Context
import android.util.Log
import java.io.File
import java.io.FileOutputStream
import java.nio.LongBuffer
import kotlin.math.exp
import kotlin.math.max

data class ModelScanResult(
    val finalClass: Int,
    val rawClass: Int,
    val confidence: Float,
    val probabilities: FloatArray,
    val labelName: String,
    val isPhishing: Boolean
)

class PhishingClassifier(private val context: Context) {

    private val ortEnv: OrtEnvironment = OrtEnvironment.getEnvironment()
    private val ortSession: OrtSession
    private val tokenizer = HFTokenizer(context, maxLength = MAX_LENGTH)

    init {
        val modelFile = copyAssetToCache("model_int8.onnx")
        ortSession = ortEnv.createSession(modelFile.absolutePath)
        runArchitectureAudit()
    }

    fun classify(text: String): ModelScanResult {
        return runCatching {
            val tokenized = tokenizer.encode(text)

            val logits = runInference(
                inputIds = tokenized.inputIds,
                attentionMask = tokenized.attentionMask,
                tokenTypeIds = tokenized.tokenTypeIds
            )

            val probabilities = softmax(logits)
            val rawClass = probabilities.indices.maxByOrNull { probabilities[it] } ?: SAFE_CLASS
            val modelConfidence = probabilities[rawClass]
            val calibrated = calibrateClass(
                text = text,
                rawClass = rawClass,
                modelConfidence = modelConfidence
            )

            ModelScanResult(
                finalClass = calibrated.first,
                rawClass = rawClass,
                confidence = calibrated.second,
                probabilities = probabilities,
                labelName = className(calibrated.first),
                isPhishing = calibrated.first != SAFE_CLASS
            )
        }.getOrElse { err ->
            Log.e(TAG, "Classification failure. Falling back to safe class.", err)
            ModelScanResult(
                finalClass = SAFE_CLASS,
                rawClass = SAFE_CLASS,
                confidence = 1.0f,
                probabilities = floatArrayOf(1.0f, 0.0f, 0.0f, 0.0f),
                labelName = className(SAFE_CLASS),
                isPhishing = false
            )
        }
    }

    private fun calibrateClass(
        text: String,
        rawClass: Int,
        modelConfidence: Float
    ): Pair<Int, Float> {
        val normalized = text.lowercase()
        val intentScore = phishingIntentScore(normalized)

        // Hard guardrail against false positives on casual chat.
        if (isLikelyCasualBenign(normalized) && intentScore == 0) {
            return Pair(SAFE_CLASS, max(0.90f, modelConfidence))
        }

        val suspiciousUrlScore = suspiciousUrlScore(normalized)
        if (suspiciousUrlScore >= 2) {
            return Pair(URL_PHISHING_CLASS, max(modelConfidence, 0.92f))
        }

        val smsScore = smsPhishingScore(normalized)
        if (smsScore >= 2) {
            return Pair(SMS_PHISHING_CLASS, max(modelConfidence, 0.88f))
        }

        val emailScore = emailPhishingScore(normalized)
        if (emailScore >= 2) {
            return Pair(EMAIL_PHISHING_CLASS, max(modelConfidence, 0.86f))
        }

        if (modelConfidence < CONFIDENCE_THRESHOLD) {
            return Pair(SAFE_CLASS, modelConfidence)
        }

        // If model is confident but there is zero phishing signal, keep it safe.
        if (intentScore == 0) {
            return Pair(SAFE_CLASS, modelConfidence)
        }

        return when (rawClass) {
            SMS_SOURCE_MODEL_CLASS -> Pair(SMS_PHISHING_CLASS, modelConfidence)
            EMAIL_SOURCE_MODEL_CLASS -> Pair(EMAIL_PHISHING_CLASS, modelConfidence)
            else -> Pair(SAFE_CLASS, modelConfidence)
        }
    }

    private fun suspiciousUrlScore(text: String): Int {
        val urlRegex = Regex("""\b((https?://|www\.)[^\s]+)\b""")
        val urls = urlRegex.findAll(text).map { it.value }.toList()
        if (urls.isEmpty()) {
            return 0
        }
        var score = 0
        val suspiciousKeywords = listOf(
            "login", "verify", "update", "secure", "wallet", "bank",
            "otp", "kyc", "claim", "gift", "password"
        )
        val shorteners = listOf("bit.ly", "tinyurl.com", "t.co", "cutt.ly", "goo.gl")
        val badTlds = listOf(".ru", ".cn", ".top", ".xyz", ".click", ".info", ".cc")

        for (url in urls) {
            val u = url.lowercase()
            if (shorteners.any { u.contains(it) }) score++
            if (badTlds.any { u.contains(it) }) score++
            if (suspiciousKeywords.any { u.contains(it) }) score++
            if (Regex("""https?://\d{1,3}(\.\d{1,3}){3}""").containsMatchIn(u)) score += 2
            val dotCount = u.count { it == '.' }
            if (dotCount >= 4) score++
            if (u.contains("@")) score++
        }
        return score
    }

    private fun smsPhishingScore(text: String): Int {
        var score = 0
        if (text.length <= 220) score++
        if (Regex("""\b(rs|inr|otp|txn|upi|wallet|sim|kyc)\b""").containsMatchIn(text)) score++
        if (Regex("""\b(urgent|immediately|blocked|suspended|frozen|final alert)\b""").containsMatchIn(text)) score++
        if (Regex("""\b(bit\.ly|tinyurl\.com|short\.link|t\.co)\b""").containsMatchIn(text)) score++
        return score
    }

    private fun emailPhishingScore(text: String): Int {
        var score = 0
        if (text.contains("subject:")) score++
        if (Regex("""\b(dear|regards|helpdesk|it team|hr|payroll|mailbox|outlook|microsoft)\b""").containsMatchIn(text)) score++
        if (Regex("""\b(verify|reset|credential|password|attachment|macro|invoice)\b""").containsMatchIn(text)) score++
        if (Regex("""\b(account suspended|security alert|sign-?in detected)\b""").containsMatchIn(text)) score++
        return score
    }

    private fun phishingIntentScore(text: String): Int {
        var score = 0
        if (Regex("""\b(click|verify|login|sign in|password|otp|account|bank|wallet|kyc|update)\b""").containsMatchIn(text)) score++
        if (Regex("""\b(urgent|immediately|final warning|suspended|blocked|frozen|limited)\b""").containsMatchIn(text)) score++
        if (Regex("""\b(http://|https://|www\.)""").containsMatchIn(text)) score++
        if (Regex("""\b(pay|payment|fee|fine|prize|gift|reward|won)\b""").containsMatchIn(text)) score++
        return score
    }

    private fun isLikelyCasualBenign(text: String): Boolean {
        val compact = text.trim()
        if (compact.isBlank()) return true
        if (compact.length > 60) return false

        val normalized = compact.replace(Regex("""[^\p{L}\p{N}\s]"""), " ")
            .replace(Regex("""\s+"""), " ")
            .trim()
        if (normalized.isBlank()) return true

        val casualTerms = setOf(
            "hi", "hello", "hey", "yo", "ok", "okay", "thanks", "thank you",
            "good morning", "good afternoon", "good evening", "gm", "gn",
            "how are you", "whats up", "sup", "bye", "see you"
        )

        if (casualTerms.contains(normalized)) return true

        val tokens = normalized.split(" ")
        if (tokens.size <= 3 && tokens.all { token ->
                token in setOf("hi", "hello", "hey", "ok", "okay", "thanks", "bye", "gm", "gn")
            }) {
            return true
        }
        return false
    }

    private fun className(classId: Int): String {
        return when (classId) {
            SAFE_CLASS -> "Legit"
            EMAIL_PHISHING_CLASS -> "Email Phishing"
            SMS_PHISHING_CLASS -> "SMS Phishing"
            URL_PHISHING_CLASS -> "URL Phishing"
            else -> "Unknown"
        }
    }

    private fun runArchitectureAudit() {
        val expectedInputs = setOf(INPUT_IDS, ATTENTION_MASK, TOKEN_TYPE_IDS)
        val actualInputs = ortSession.inputInfo.keys
        require(expectedInputs == actualInputs) {
            "ONNX input mismatch. expected=$expectedInputs actual=$actualInputs"
        }

        expectedInputs.forEach { inputName ->
            val info = ortSession.inputInfo[inputName]?.info as? TensorInfo
                ?: error("Input '$inputName' missing TensorInfo")
            require(info.type == OnnxJavaType.INT64) {
                "Input '$inputName' must be int64 but was ${info.type}"
            }
            require(info.shape.size == 2) {
                "Input '$inputName' must be rank-2 but was shape=${info.shape.contentToString()}"
            }
        }

        val outputInfo = ortSession.outputInfo[LOGITS_OUTPUT]?.info as? TensorInfo
            ?: (ortSession.outputInfo.values.first().info as? TensorInfo
                ?: error("ONNX output TensorInfo missing"))

        require(outputInfo.type == OnnxJavaType.FLOAT) {
            "Output must be float32 but was ${outputInfo.type}"
        }
        require(outputInfo.shape.size == 2) {
            "Output must be rank-2 but was shape=${outputInfo.shape.contentToString()}"
        }

        val classDim = outputInfo.shape[1]
        if (classDim > 0) {
            require(classDim.toInt() == NUM_CLASSES) {
                "Output class dim must be $NUM_CLASSES but was $classDim"
            }
        }

        val testLogits = runInference(
            inputIds = LongArray(MAX_LENGTH) { if (it == 0) 101L else if (it == 1) 102L else 0L },
            attentionMask = LongArray(MAX_LENGTH) { if (it <= 1) 1L else 0L },
            tokenTypeIds = LongArray(MAX_LENGTH)
        )

        require(testLogits.size == NUM_CLASSES) {
            "Output logits size must be $NUM_CLASSES but was ${testLogits.size}"
        }

        Log.i(
            TAG,
            "Audit OK: inputs=$actualInputs, outputType=${outputInfo.type}, outputShape=${outputInfo.shape.contentToString()}, tensorShape=(1,$MAX_LENGTH)"
        )
    }

    private fun runInference(
        inputIds: LongArray,
        attentionMask: LongArray,
        tokenTypeIds: LongArray
    ): FloatArray {
        require(inputIds.size == MAX_LENGTH) { "input_ids must be length $MAX_LENGTH" }
        require(attentionMask.size == MAX_LENGTH) { "attention_mask must be length $MAX_LENGTH" }
        require(tokenTypeIds.size == MAX_LENGTH) { "token_type_ids must be length $MAX_LENGTH" }

        OnnxTensor.createTensor(ortEnv, LongBuffer.wrap(inputIds), longArrayOf(1, MAX_LENGTH.toLong())).use { inputTensor ->
            OnnxTensor.createTensor(ortEnv, LongBuffer.wrap(attentionMask), longArrayOf(1, MAX_LENGTH.toLong())).use { maskTensor ->
                OnnxTensor.createTensor(ortEnv, LongBuffer.wrap(tokenTypeIds), longArrayOf(1, MAX_LENGTH.toLong())).use { typeTensor ->
                    val inputs = mapOf(
                        INPUT_IDS to inputTensor,
                        ATTENTION_MASK to maskTensor,
                        TOKEN_TYPE_IDS to typeTensor
                    )

                    ortSession.run(inputs).use { outputs ->
                        val value = outputs[0].value
                        return extractLogits(value)
                    }
                }
            }
        }
    }

    private fun extractLogits(value: Any): FloatArray {
        return when (value) {
            is Array<*> -> {
                val first = value.firstOrNull()
                when (first) {
                    is FloatArray -> first.copyOf()
                    is DoubleArray -> first.map { it.toFloat() }.toFloatArray()
                    is Array<*> -> first.mapNotNull { (it as? Number)?.toFloat() }.toFloatArray()
                    else -> error("Unsupported output payload type: ${first?.javaClass}")
                }
            }
            is FloatArray -> value.copyOf()
            is DoubleArray -> value.map { it.toFloat() }.toFloatArray()
            else -> error("Unsupported output value type: ${value.javaClass}")
        }
    }

    private fun softmax(logits: FloatArray): FloatArray {
        val maxLogit = logits.maxOrNull() ?: 0f
        val expValues = FloatArray(logits.size)
        var sum = 0f
        for (i in logits.indices) {
            expValues[i] = exp((logits[i] - maxLogit).toDouble()).toFloat()
            sum += expValues[i]
        }
        if (sum <= 0f) {
            return FloatArray(logits.size) { 1f / logits.size }
        }
        return FloatArray(logits.size) { idx -> expValues[idx] / sum }
    }

    private fun copyAssetToCache(fileName: String): File {
        val outputFile = File(context.cacheDir, fileName)
        context.assets.open(fileName).use { input ->
            FileOutputStream(outputFile, false).use { output ->
                input.copyTo(output)
                output.flush()
            }
        }
        return outputFile
    }

    companion object {
        const val TAG = "PhishingClassifier"
        const val MAX_LENGTH = 128
        const val NUM_CLASSES = 4
        const val SAFE_CLASS = 0
        const val EMAIL_PHISHING_CLASS = 1
        const val SMS_PHISHING_CLASS = 2
        const val URL_PHISHING_CLASS = 3
        const val CONFIDENCE_THRESHOLD = 0.75f
        const val PHISHING_CLASS = EMAIL_PHISHING_CLASS

        // Current trained model classes are mapped into app classes by calibrateClass().
        private const val EMAIL_SOURCE_MODEL_CLASS = 1
        private const val SMS_SOURCE_MODEL_CLASS = 2

        private const val INPUT_IDS = "input_ids"
        private const val ATTENTION_MASK = "attention_mask"
        private const val TOKEN_TYPE_IDS = "token_type_ids"
        private const val LOGITS_OUTPUT = "logits"
    }
}
