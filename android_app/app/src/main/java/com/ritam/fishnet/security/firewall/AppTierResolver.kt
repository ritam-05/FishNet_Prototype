package com.ritam.fishnet.security.firewall

import com.ritam.fishnet.security.AppTier
import java.util.Locale

class AppTierResolver {
    fun resolve(packageName: String): AppTier {
        val pkg = packageName.lowercase(Locale.ROOT)
        return when {
            pkg.startsWith("com.android.") ||
                pkg.startsWith("com.google.android.") ||
                pkg.startsWith("com.samsung.") -> AppTier.SYSTEM

            pkg.contains("facebook") ||
                pkg.contains("instagram") ||
                pkg.contains("whatsapp") ||
                pkg.contains("telegram") ||
                pkg.contains("linkedin") -> AppTier.SOCIAL

            pkg.contains("phonepe") ||
                pkg.contains("paytm") ||
                pkg.contains("paisa.user") ||
                pkg.contains("bank") -> AppTier.FINANCIAL_TRUSTED

            pkg.contains("gmail") ||
                pkg.contains("outlook") ||
                pkg.contains("yahoo") ||
                pkg.contains("samsung.android.email") ||
                pkg.contains("mail") -> AppTier.EMAIL

            pkg.contains("spotify") ||
                pkg.contains("music") ||
                pkg.contains("youtube") -> AppTier.MEDIA

            else -> AppTier.UNKNOWN
        }
    }
}
