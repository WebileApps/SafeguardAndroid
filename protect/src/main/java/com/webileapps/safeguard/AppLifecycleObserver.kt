package com.webileapps.safeguard

import ScreenSharingDetector
import android.content.Context
import android.content.pm.PackageManager
import android.provider.Settings
import android.util.Log
import android.widget.Toast
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner


class AppLifecycleObserver(private val context: Context) : DefaultLifecycleObserver {

    var status = false

    override fun onStart(owner: LifecycleOwner) {
        Log.e("APP>>>", "App is in Foreground")

        // Perform security checks in sequence
        performSecurityChecks()
    }

    private fun performSecurityChecks() {
        val securityChecker: SecurityChecker = SecurityConfigManager.getSecurityChecker()
        // Root check
        context.checkRoot(securityChecker) { rootCheckPassed ->
            if (!rootCheckPassed) return@checkRoot

            // Developer options check
            context.checkDeveloperOptions(securityChecker) { devOptionsCheckPassed ->
                if (!devOptionsCheckPassed) return@checkDeveloperOptions

                // Malware check
                context.checkMalware(securityChecker) { malwareCheckPassed ->
                    if (!malwareCheckPassed) return@checkMalware

                    // Screen mirroring check
                    context.checkScreenMirroring(securityChecker) { mirroringCheckPassed ->
                        if (!mirroringCheckPassed) return@checkScreenMirroring

                        // Application spoofing check
                        context.checkApplicationSpoofing(securityChecker) { spoofingCheckPassed ->
                            if (!spoofingCheckPassed) return@checkApplicationSpoofing

                            // Keylogger check
                            context.checkKeyLoggerDetection(securityChecker) { keyloggerCheckPassed ->
                                if (!keyloggerCheckPassed) return@checkKeyLoggerDetection

                                // Network security check
                                context.checkNetwork(securityChecker) { networkCheckPassed ->
                                    if (!networkCheckPassed) return@checkNetwork

                                    // All security checks passed
                                    Log.d("Security", "All security checks completed")
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    override fun onStop(owner: LifecycleOwner) {
        Log.e("APP>>>", "App is in Background")
        networkMonitor.stopMonitoring()
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
