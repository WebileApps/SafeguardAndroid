package com.kfintech.protect

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.provider.Settings
import android.app.ActivityManager
import android.app.AlertDialog
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.media.projection.MediaProjectionManager
import android.os.PowerManager
import android.util.Log
import com.kfintech.protect.NetworkUtils.isProxySet
import com.kfintech.protect.NetworkUtils.isVPNActive
import com.kfintech.protect.NetworkUtils.isWifiSecure
import com.scottyab.rootbeer.RootBeer
import java.security.MessageDigest
import kotlin.system.exitProcess

class SecurityChecker(private val context: Context, private val config: SecurityConfig = SecurityConfig()) {
    
    sealed class SecurityCheck {
        object Success : SecurityCheck()
        data class Warning(val message: String) : SecurityCheck()
        data class Critical(val message: String) : SecurityCheck()
    }

    // Configuration class to control security check behavior
    data class SecurityConfig(
        val treatRootAsWarning: Boolean = false,
        val treatDeveloperOptionsAsWarning: Boolean = false,
        val treatMalwareAsWarning: Boolean = false,
        val treatTamperingAsWarning: Boolean = false,
        val appSpoofingAsWarning: Boolean = false
    )

    // Check for rooted device
    fun checkRootStatus(): SecurityCheck {
        val rootBeer = RootUtil.isDeviceRooted

        return if (rootBeer) {
            if (config.treatRootAsWarning) {
                SecurityCheck.Warning(context.getString(R.string.rooted_warning))
            } else {
                SecurityCheck.Critical(context.getString(R.string.rooted_critical))
            }
        } else {
            SecurityCheck.Success
        }
    }

    // Check developer options
    fun checkDeveloperOptions(): SecurityCheck {
        val developerMode = Settings.Secure.getInt(
            context.contentResolver,
            Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0
        ) != 0

        val usbDebugging = Settings.Global.getInt(
            context.contentResolver,
            Settings.Global.ADB_ENABLED, 0
        ) != 0

        val mockLocation = Settings.Secure.getString(
            context.contentResolver,
            Settings.Secure.ALLOW_MOCK_LOCATION
        ) != "0"



        return when {
            developerMode -> createDevOptionsResponse(context.getString(R.string.developer_options_warning))
            usbDebugging -> createDevOptionsResponse(context.getString(R.string.usb_debugging_warning))
            mockLocation -> createDevOptionsResponse(context.getString(R.string.mock_location_warning))
            isTimeManipulated(context) -> createDevOptionsResponse(context.getString(R.string.auto_time_warning))
            else -> SecurityCheck.Success
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

    private fun createDevOptionsResponse(message: String): SecurityCheck {
        return if (config.treatDeveloperOptionsAsWarning) {
            SecurityCheck.Warning("$message This may pose security risks.")
        } else {
            SecurityCheck.Critical("$message Please disable it to continue using the application.")
        }
    }

    // Check network security
    fun checkNetworkSecurity(): SecurityCheck {
        val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val network = connectivityManager.activeNetwork
        val capabilities = connectivityManager.getNetworkCapabilities(network)

        return when {
            capabilities == null -> SecurityCheck.Warning("No active network connection")
            isVPNActive(context) ->
                SecurityCheck.Warning(context.getString(R.string.vpn_warning))
            isProxySet(context) ->
                SecurityCheck.Warning(context.getString(R.string.proxy_warning))
            !isWifiSecure(context) ->
                SecurityCheck.Warning(context.getString(R.string.usecured_network_warning))
            else -> SecurityCheck.Success
        }
    }

    // Check for malware and tampering
    fun checkMalwareAndTampering(): SecurityCheck {
        try {
            val packageInfo = context.packageManager.getPackageInfo(
                context.packageName,
                PackageManager.GET_SIGNATURES
            )
            
            val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                packageInfo.signingInfo.apkContentsSigners
            } else {
                @Suppress("DEPRECATION")
                packageInfo.signatures
            }

            if (!verifySignature(signatures)) {
                return if (config.treatTamperingAsWarning) {
                    SecurityCheck.Warning("Application signature verification failed. This may indicate tampering.")
                } else {
                    SecurityCheck.Critical("Application signature is not as expected. Please reinstall from official source.")
                }
            }

            if (Settings.canDrawOverlays(context)) {
                return if (config.treatMalwareAsWarning) {
                    SecurityCheck.Warning("Screen overlay detected. This could pose security risks.")
                } else {
                    SecurityCheck.Critical("Screen overlay detected, which could be malicious.")
                }
            }

            return SecurityCheck.Success
        } catch (e: Exception) {
            return if (config.treatMalwareAsWarning) {
                SecurityCheck.Warning("Security verification failed. This may pose risks.")
            } else {
                SecurityCheck.Critical("Security verification failed.")
            }
        }
    }

    // Check for screen mirroring and remote access
    fun checkScreenMirroring(): SecurityCheck {
        val projectionManager = context.getSystemService(Context.MEDIA_PROJECTION_SERVICE) as MediaProjectionManager
        val activityManager = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        if(ScreenSharingDetector.isScreenSharingActive(context)){
            return SecurityCheck.Warning(context.getString(R.string.screen_sharing_warniong))
        }else if(ScreenSharingDetector.isScreenMirrored(context)){
            return SecurityCheck.Warning(context.getString(R.string.screen_mirroring_warniong))
        } else if (isScreenRecording()) {
            return SecurityCheck.Warning(context.getString(R.string.screen_recording_warniong))
        }
        return SecurityCheck.Success
    }
 // Check for app spoofing
    fun checkAppSpoofing(): SecurityCheck {

     if (context.packageName != com.kfintech.protect.getPackageName(context)) {
         Log.e("Security", "Application spoofing detected")
         return SecurityCheck.Warning(context.getString(R.string.app_spoofing_warniong))
         // System.exit(0)
     }
     return SecurityCheck.Success
    }
 // Check for app spoofing
    fun checkKeyLoggerDetection(): SecurityCheck {
     if (KeyloggerDetection.isAccessibilityServiceEnabled(context)) {
         return SecurityCheck.Warning(context.getString(R.string.accecibility_warniong))

     }/* else {
         return SecurityCheck.Warning(context.getString(R.string.accecibility_not_warniong))
     }*/
     return SecurityCheck.Success
    }

    private fun isScreenRecording(): Boolean {
        // This is a simplified check. In production, you'd want more sophisticated detection
        val projectionManager = context.getSystemService(Context.MEDIA_PROJECTION_SERVICE) as MediaProjectionManager
        return false // Placeholder - actual implementation would be more complex
    }

    private fun verifySignature(signatures: Array<Signature>): Boolean {
        // In production, you would compare against your known good signature
        return signatures.isNotEmpty()
    }

    companion object {
        fun showSecurityDialog(context: Context, message: String, isCritical: Boolean) {
            AlertDialog.Builder(context)
                .setTitle(if (isCritical) "Security Error" else "Security Warning")
                .setMessage(message)
                .setPositiveButton("OK") { dialog, _ ->
                    dialog.dismiss()
                    if (isCritical) {
                        exitProcess(0)
                    }
                }
                .setCancelable(!isCritical)
                .show()
        }
    }
}
