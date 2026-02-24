package com.ritam.fishnet

import android.content.Context
import org.json.JSONObject

data class TokenizedInput(
    val inputIds: LongArray,
    val attentionMask: LongArray,
    val tokenTypeIds: LongArray
)

class HFTokenizer(
    private val context: Context,
    private val maxLength: Int = 128
) {

    private val tokenizer: BertRuntimeWordPieceTokenizer by lazy {
        BertRuntimeWordPieceTokenizer(context)
    }

    fun encode(text: String): TokenizedInput {
        return tokenizer.encode(text, maxLength)
    }

    private class BertRuntimeWordPieceTokenizer(context: Context) {
        private val vocab: Map<String, Long>
        private val unkId: Long
        private val clsId: Long
        private val sepId: Long
        private val padId: Long

        init {
            val tokenizerJson = context.assets.open("tokenizer.json").bufferedReader().use { it.readText() }
            val root = JSONObject(tokenizerJson)
            val model = root.getJSONObject("model")
            val vocabJson = model.getJSONObject("vocab")

            val indexMap = HashMap<String, Long>(vocabJson.length() + 8)
            val keys = vocabJson.keys()
            while (keys.hasNext()) {
                val token = keys.next()
                indexMap[token] = vocabJson.getLong(token)
            }
            vocab = indexMap

            // Resolve IDs from tokenizer config first, then fall back to common BERT IDs.
            unkId = resolveSpecialTokenId(root, "[UNK]") ?: vocab["[UNK]"] ?: 100L
            clsId = resolveSpecialTokenId(root, "[CLS]") ?: vocab["[CLS]"] ?: 101L
            sepId = resolveSpecialTokenId(root, "[SEP]") ?: vocab["[SEP]"] ?: 102L
            padId = resolveSpecialTokenId(root, "[PAD]") ?: vocab["[PAD]"] ?: 0L
        }

        fun encode(text: String, maxLength: Int): TokenizedInput {
            val tokens = ArrayList<String>(maxLength)
            tokens.add("[CLS]")

            val words = normalizeAndSplit(text)
            for (word in words) {
                tokens.addAll(splitWordPiece(word))
            }
            tokens.add("[SEP]")

            val ids = LongArray(maxLength) { padId }
            val attention = LongArray(maxLength) { 0L }
            val typeIds = LongArray(maxLength) { 0L }

            val limit = minOf(tokens.size, maxLength)
            for (i in 0 until limit) {
                ids[i] = vocab[tokens[i]] ?: unkId
                attention[i] = 1L
            }
            if (tokens.size > maxLength) {
                ids[maxLength - 1] = sepId
                attention[maxLength - 1] = 1L
            }

            // Keep these explicit so the post-processor shape matches expected BERT format.
            ids[0] = clsId
            if (limit > 0) {
                val sepPosition = minOf(limit - 1, maxLength - 1)
                ids[sepPosition] = if (tokens.size >= maxLength) sepId else ids[sepPosition]
            }

            return TokenizedInput(
                inputIds = ids,
                attentionMask = attention,
                tokenTypeIds = typeIds
            )
        }

        private fun normalizeAndSplit(text: String): List<String> {
            return text.lowercase()
                .replace(Regex("""[^\p{L}\p{N}\s]"""), " ")
                .split(Regex("""\s+"""))
                .filter { it.isNotBlank() }
        }

        private fun splitWordPiece(word: String): List<String> {
            if (vocab.containsKey(word)) return listOf(word)

            val result = mutableListOf<String>()
            var start = 0
            while (start < word.length) {
                var end = word.length
                var foundToken: String? = null
                while (start < end) {
                    var sub = word.substring(start, end)
                    if (start > 0) sub = "##$sub"
                    if (vocab.containsKey(sub)) {
                        foundToken = sub
                        break
                    }
                    end--
                }
                if (foundToken == null) return listOf("[UNK]")
                result.add(foundToken)
                start = end
            }
            return result
        }

        private fun resolveSpecialTokenId(root: JSONObject, token: String): Long? {
            val addedTokens = root.optJSONArray("added_tokens") ?: return null
            for (i in 0 until addedTokens.length()) {
                val item = addedTokens.optJSONObject(i) ?: continue
                if (item.optString("content") == token) {
                    return item.optLong("id")
                }
            }
            return null
        }
    }
}

