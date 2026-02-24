package com.ritam.fishnet

import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.provider.Settings
import android.service.notification.NotificationListenerService

class BootCompletedReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent?) {
        val bootAction = intent?.action ?: return
        if (
            bootAction != Intent.ACTION_BOOT_COMPLETED &&
            bootAction != Intent.ACTION_LOCKED_BOOT_COMPLETED &&
            bootAction != Intent.ACTION_MY_PACKAGE_REPLACED
        ) {
            return
        }
        if (!AppSettings.isProtectionEnabled(context)) return

        if (isNotificationAccessEnabled(context)) {
            runCatching {
                NotificationListenerService.requestRebind(
                    ComponentName(context, NotificationService::class.java)
                )
            }
            runCatching {
                context.startService(
                    Intent(context, NotificationService::class.java).apply {
                        this.action = NotificationService.ACTION_SCAN_EXISTING_NOTIFICATIONS
                    }
                )
            }
        }

        if (bootAction == Intent.ACTION_LOCKED_BOOT_COMPLETED) return

        val launchIntent = Intent(context, MainActivity::class.java).apply {
            action = Intent.ACTION_MAIN
            addCategory(Intent.CATEGORY_LAUNCHER)
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        runCatching { context.startActivity(launchIntent) }
    }

    private fun isNotificationAccessEnabled(context: Context): Boolean {
        val enabledListeners = Settings.Secure.getString(
            context.contentResolver,
            "enabled_notification_listeners"
        ) ?: ""
        return enabledListeners.contains(context.packageName)
    }
}
