package com.webileapps.safeguard


import android.content.Context
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.telephony.PhoneStateListener
import android.telephony.TelephonyManager
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
        telephonyManager.listen(phoneStateListener, PhoneStateListener.LISTEN_CALL_STATE)
        networkMonitor = NetworkMonitor(context)
        networkMonitor.startMonitoring {
            SecurityConfigManager.getSecurityChecker().showSecurityDialog(AppActivity.context, context.getString(R.string.screen_sharing_warning), false) {

            }
        }

    }

    private fun performSecurityChecks() {
         securityChecker = SecurityConfigManager.getSecurityChecker()



            // Root check
        context.checkRoot(securityChecker) { rootCheckPassed ->
            if (!rootCheckPassed) return@checkRoot

            // Developer options check
            context.checkDeveloperOptions(securityChecker) { devOptionsCheckPassed ->
                if (!devOptionsCheckPassed) return@checkDeveloperOptions

                context.appSignatureCheck(securityChecker){ isAppSignatureValid ->
                    if(!isAppSignatureValid) return@appSignatureCheck

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

                                    val filter = IntentFilter(ConnectivityManager.CONNECTIVITY_ACTION)
                                    context.registerReceiver(networkChangeReceiver, filter)  /* // Network security check
                                    context.checkNetwork(securityChecker) { networkCheckPassed ->
                                        if (!networkCheckPassed) return@checkNetwork

                                        // All security checks passed
                                        Log.d("Security", "All security checks completed")
                                    }*/
                                }
                            }
                        }
                    }
                }
                // Malware check

            }
        }
    }

    override fun onStop(owner: LifecycleOwner) {
        Log.e("APP>>>", "App is in Background")
        try {
            telephonyManager.listen(phoneStateListener, PhoneStateListener.LISTEN_NONE)
        }catch (e: Exception){

        }

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

    private val telephonyManager: TelephonyManager = context.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
    private val phoneStateListener = object : PhoneStateListener() {
        override fun onCallStateChanged(state: Int, incomingNumber: String?) {
            super.onCallStateChanged(state, incomingNumber)

            when (state) {
                TelephonyManager.CALL_STATE_IDLE -> {

                }
                TelephonyManager.CALL_STATE_RINGING -> {

                }
                TelephonyManager.CALL_STATE_OFFHOOK -> {
                    context.checkInvoiceCall(SecurityConfigManager.getSecurityChecker(),true){

                    }
                }
            }
        }
    }

}
