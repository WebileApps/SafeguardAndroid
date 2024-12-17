package com.webileapps.safeguard


import android.content.Context
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.util.Log
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner


class AppLifecycleObserver(private val context: Context) : DefaultLifecycleObserver {

        private var networkChangeReceiver: NetworkChangeReceiver? = null
    lateinit var securityChecker: SecurityChecker

    var status = false

    override fun onStart(owner: LifecycleOwner) {
        Log.e("APP>>>", "App is in Foreground")

        // Perform security checks in sequence

        performSecurityChecks()
        networkMonitor = NetworkMonitor(context)
        networkMonitor.startMonitoring {
            SecurityConfigManager.getSecurityChecker().showSecurityDialog(AppActivity.context, context.getString(R.string.screen_sharing_warning), false) {

            }
        }

    }

    private fun performSecurityChecks() {
        securityChecker = SecurityConfigManager.getSecurityChecker()
        securityChecker.runSecurityChecks()
    }

    override fun onStop(owner: LifecycleOwner) {
        Log.e("APP>>>", "App is in Background")

         networkMonitor.stopMonitoring()
        try {
            context.unregisterReceiver(networkChangeReceiver)
        } catch (e: IllegalArgumentException) {
            Log.e("TAG", "Error while unregistering receiver: ${e.message}")
        }
    }

    companion object {
        private lateinit var networkMonitor: NetworkMonitor
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
