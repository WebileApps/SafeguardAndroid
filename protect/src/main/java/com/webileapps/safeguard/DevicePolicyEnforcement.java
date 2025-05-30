package com.webileapps.safeguard;

import android.content.Context;
import android.provider.Settings;
import android.util.Log;

public class DevicePolicyEnforcement {
    
    public static boolean enforceDevicePolicy(Context context) {
        boolean isDevOptionsEnabled = isDeveloperOptionsEnabled(context);
        boolean isUSBDebuggingEnabled = isUSBDebuggingEnabled(context);
        boolean isMockLocationEnabled = MockLocationDetection.isMockLocationEnabled(context);
        boolean isTimeManipulated = isTimeManipulated(context);

        // Take appropriate action if any violation is detected
        // showPolicyViolationDialog(context);
        return isDevOptionsEnabled || isUSBDebuggingEnabled || isMockLocationEnabled || isTimeManipulated;
    }
    private static boolean isDeveloperOptionsEnabled(Context context) {
        try {
            int devOptions = Settings.Global.getInt(
                context.getContentResolver(),
                Settings.Global.DEVELOPMENT_SETTINGS_ENABLED
            );
            return devOptions == 1;
        } catch (Settings.SettingNotFoundException e) {

            return false;
        }
    }
    private static boolean isUSBDebuggingEnabled(Context context) {
        try {
            int adbEnabled = Settings.Global.getInt(
                context.getContentResolver(), 
                Settings.Global.ADB_ENABLED
            );
            return adbEnabled == 1;
        } catch (Settings.SettingNotFoundException e) {

            return false;
        }
    }
    private static boolean isTimeManipulated(Context context) {
        try {
            int autoTime = Settings.Global.getInt(
                context.getContentResolver(),
                Settings.Global.AUTO_TIME
            );
            int autoTimeZone = Settings.Global.getInt(
                context.getContentResolver(),
                Settings.Global.AUTO_TIME_ZONE
            );
            return autoTime == 0 || autoTimeZone == 0;
        } catch (Settings.SettingNotFoundException e) {

            return false;
        }
    }
}
