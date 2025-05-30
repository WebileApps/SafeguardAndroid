package com.webileapps.safeguard;

import android.content.Context;
import android.provider.Settings;

public class KeyloggerDetection {
    public static boolean isAccessibilityServiceEnabled(Context context) {
        try {
            String enabledServices = Settings.Secure.getString(
                context.getContentResolver(),
                Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
            );
            if (enabledServices != null && enabledServices.contains(context.getPackageName())) {
                return true;
            }
        } catch (Exception ignored) {
        }
        return false;
    }
}
