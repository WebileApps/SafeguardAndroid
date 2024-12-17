package com.webileapps.safeguard


import android.content.Context
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.util.Log
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner


class AppLifecycleObserver(private val context: Context) : DefaultLifecycleObserver {

    lateinit var securityChecker: SecurityChecker

    override fun onStart(owner: LifecycleOwner) {
        Log.e("APP>>>", "App is in Foreground")

        // Perform security checks in sequence
        performSecurityChecks()
    }

    private fun performSecurityChecks() {
        securityChecker = SecurityConfigManager.getSecurityChecker()
        securityChecker.runSecurityChecks()
    }

    override fun onStop(owner: LifecycleOwner) {
        Log.e("APP>>>", "App is in Background")
        securityChecker.cleanup()
    }

    private fun detectOverlayApps(context: Context) {
        val pm = context.packageManager
        for (packageInfo in pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)) {
            if (packageInfo.requestedPermissions != null) {
                for (permission in packageInfo.requestedPermissions!!) {
                    if (permission == "android.permission.SYSTEM_ALERT_WINDOW") {
                        //showToast(context,"App using SYSTEM_ALERT_WINDOW: " + packageInfo.packageName)
                    }
                }
            }
        }
    }

}
