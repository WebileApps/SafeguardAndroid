package com.kfintech.protect

import ScreenSharingDetector
import android.content.Context
import android.content.pm.PackageManager
import android.provider.Settings
import android.util.Log
import android.widget.Toast
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner


class AppLifecycleObserver(private val context: Context) : DefaultLifecycleObserver {
    override fun onStart(owner: LifecycleOwner) {
        // App enters the foreground
        Log.e("APP>>>", "App is in Foreground")

        showToast(context,"App is in Foreground ${context.getPackageName()}")

        /*TODO: Device Policy enforcement such as detection of developer option, USB debugging, Mock Location, time settings manipulation, etc. shall be configured*/
        if(DevicePolicyEnforcement.enforceDevicePolicy(context)){
            showToast(context,"Device policy violations detected. Please disable developer options, USB debugging, or mock locations, and ensure the system time is correct.")
        }


        /*TODO: Application Spoofing Detection*/
        if (context.packageName != getPackageName(context)) {
            Log.e("Security", "Application spoofing detected")
            showToast(context,"Application spoofing detected")
           // System.exit(0)
        }

        //  showToast(this,"Anand>>>>>");
        /*TODO: Overlay Malware Prevention*/
        val isOverlayEnabled = Settings.canDrawOverlays(context)
        if (isOverlayEnabled) {
           showToast( context,"Overlay detected")
        }

        /*TODO: Overlay Malware Detection*/
        detectOverlayApps(context)

        if(ScreenSharingDetector.isScreenSharingActive(context)||ScreenSharingDetector.isScreenMirrored(context)){
            showToast(context,"Screen sharing or mirroring detected!")
        }

        // Use if-else to display the appropriate message
        if (KeyloggerDetection.isAccessibilityServiceEnabled(context)) {
            showToast(context, "Accessibility Service is enabled for this app")

        } else {
          showToast(
                context, "Accessibility Service is NOT enabled for this app")
        }




        /*TODO: Mobile application shall check new network connections or connections for unsecured networks like VPN connection, proxy and unsecured Wi-Fi connections.77~@*/
       /* networkChangeReceiver = NetworkChangeReceiver()
        val filter = IntentFilter(ConnectivityManager.CONNECTIVITY_ACTION)
        registerReceiver(networkChangeReceiver, filter)*/
        networkMonitor = NetworkMonitor(context)
        networkMonitor.startMonitoring { isConnected ->
            if(isConnected){
                if (NetworkUtils.isVPNActive(context)) {
                    // Handle VPN detection
                    showToast(context,"VPN is active")
                    //println("VPN is active")
                }
                if (NetworkUtils.isProxySet(context)) {
                    // Handle proxy detection
                    showToast(context,"Proxy is enabled")
                }
                if (!NetworkUtils.isWifiSecure(context)) {
                    // Handle unsecured Wi-Fi detection
                    showToast(context,"Connected to an unsecured Wi-Fi")
                }
            }

        }

    }

    override fun onStop(owner: LifecycleOwner) {
        // App enters the background
        Log.e("APP>>>", "App is in Background")
        showToast(context,"App is in Background")
        networkMonitor.stopMonitoring()
    }

    companion object {
        val TAG: String = AppLifecycleObserver::class.java.name
        private lateinit var networkMonitor: NetworkMonitor
    }


    fun detectOverlayApps(context: Context) {
        val pm = context.packageManager
        for (packageInfo in pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)) {
            if (packageInfo.requestedPermissions != null) {
                for (permission in packageInfo.requestedPermissions) {
                    if (permission == "android.permission.SYSTEM_ALERT_WINDOW") {
                        showToast(context,"App using SYSTEM_ALERT_WINDOW: " + packageInfo.packageName)
                    }
                }
            }
        }
    }
}
