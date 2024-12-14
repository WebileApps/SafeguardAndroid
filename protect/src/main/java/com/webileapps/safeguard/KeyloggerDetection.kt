package com.webileapps.safeguard

import android.content.Context
import android.provider.Settings

object KeyloggerDetection {
    fun isAccessibilityServiceEnabled(context: Context): Boolean {
        try {
            val enabledServices = Settings.Secure.getString(
                context.contentResolver,
                Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
            )
            if (enabledServices != null && enabledServices.contains(context.packageName)) {
                return true
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return false
    }
}
