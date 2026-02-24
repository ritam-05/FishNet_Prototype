package com.ritam.fishnet.security.firewall

class SpoofDetectionManager {
    private val trustedBankPackages: Map<String, Set<String>> = mapOf(
        "sbi" to setOf("com.sbi.lotusintouch"),
        "hdfc" to setOf("com.snapwork.hdfc"),
        "icici" to setOf("com.csam.icici.bank.imobile"),
        "axis" to setOf("com.axis.mobile"),
        "kotak" to setOf("com.kotak.bank.mobile")
    )

    fun isSpoofed(packageName: String, normalizedText: String): Boolean {
        val pkg = packageName.lowercase()
        for ((bankName, officialPackages) in trustedBankPackages) {
            if (normalizedText.contains(bankName) && officialPackages.none { it == pkg }) {
                return true
            }
        }
        return false
    }
}

