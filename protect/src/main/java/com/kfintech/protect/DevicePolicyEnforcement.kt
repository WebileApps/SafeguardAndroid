package com.kfintech.protect

import android.app.AlertDialog
import android.content.Context
import android.content.DialogInterface
import android.provider.Settings


object DevicePolicyEnforcement {
    @JvmStatic
    fun enforceDevicePolicy(context: Context): Boolean {
        val isDevOptionsEnabled = isDeveloperOptionsEnabled(context)
        val isUSBDebuggingEnabled = isUSBDebuggingEnabled(context)
        val isMockLocationEnabled = MockLocationDetection.isMockLocationEnabled(context)
        val isTimeManipulated = isTimeManipulated(context)

        // Take appropriate action if any violation is detected
        //  showPolicyViolationDialog(context);
        return isDevOptionsEnabled || isUSBDebuggingEnabled || isMockLocationEnabled || isTimeManipulated
    }

    private fun showPolicyViolationDialog(context: Context) {
        val builder = AlertDialog.Builder(context)
        builder.setTitle("Policy Violation Detected")
        builder.setMessage("This device does not meet the security policies required by the application.")
        builder.setCancelable(false)
        builder.setPositiveButton(
            "Exit"
        ) { dialog: DialogInterface?, which: Int -> System.exit(0) }
        builder.show()
    }

    // Individual checks (reuse the methods written above)
    private fun isDeveloperOptionsEnabled(context: Context): Boolean {
        try {
            val devOptions = Settings.Global.getInt(
                context.contentResolver,
                Settings.Global.DEVELOPMENT_SETTINGS_ENABLED
            )
            return devOptions == 1
        } catch (e: Settings.SettingNotFoundException) {
            e.printStackTrace()
            return false
        }
    }

    private fun isUSBDebuggingEnabled(context: Context): Boolean {
        try {
            val adbEnabled =
                Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED)
            return adbEnabled == 1
        } catch (e: Settings.SettingNotFoundException) {
            e.printStackTrace()
            return false
        }
    }

    private fun isTimeManipulated(context: Context): Boolean {
        try {
            val autoTime =
                Settings.Global.getInt(context.contentResolver, Settings.Global.AUTO_TIME)
            val autoTimeZone =
                Settings.Global.getInt(context.contentResolver, Settings.Global.AUTO_TIME_ZONE)
            return autoTime == 0 || autoTimeZone == 0
        } catch (e: Settings.SettingNotFoundException) {
            e.printStackTrace()
            return false
        }
    }
}
