package com.webileapps.safeguard

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
import com.kfintech.protect.R
import com.webileapps.safeguard.NetworkUtils.isProxySet
import com.webileapps.safeguard.NetworkUtils.isVPNActive
import com.webileapps.safeguard.NetworkUtils.isWifiSecure
import com.scottyab.rootbeer.RootBeer
import java.security.MessageDigest
import java.util.function.Consumer
import kotlin.system.exitProcess

class SecurityChecker(private val context: Context, private val config: SecurityConfig = SecurityConfig()) {
    
    sealed class SecurityCheck {
        object Success : SecurityCheck()
        data class Warning(val message: String) : SecurityCheck()
        data class Critical(val message: String) : SecurityCheck()
    }

    private data class SecurityDialogInfo(
        val message: String,
        val isCritical: Boolean,
        val onResponse: ((Boolean) -> Unit)? = null
    )

    private val dialogQueue = mutableListOf<SecurityDialogInfo>()
    private var isShowingDialog = false

    private fun showNextDialog(context: Context) {
        if (isShowingDialog || dialogQueue.isEmpty()) {
            return
        }

        isShowingDialog = true
        val dialogInfo = dialogQueue.removeAt(0)

        AlertDialog.Builder(context)
            .setTitle(if (dialogInfo.isCritical) "Security Error" else "Security Warning")
            .setMessage(dialogInfo.message)
            .setPositiveButton(if (dialogInfo.isCritical) "Quit" else "Continue Anyway") { dialog, _ ->
                dialog.dismiss()
                if (dialogInfo.isCritical) {
                    exitProcess(0)
                } else {
                    dialogInfo.onResponse?.invoke(true)
                    isShowingDialog = false
                    showNextDialog(context) // Show next dialog if any
                }
            }
            .setOnDismissListener {
                if (!dialogInfo.isCritical) {
                    isShowingDialog = false
                    showNextDialog(context)
                }
            }
            .setCancelable(!dialogInfo.isCritical)
            .create()
            .apply {
                setOnDismissListener {
                    if (!dialogInfo.isCritical) {
                        isShowingDialog = false
                        showNextDialog(context)
                    }
                }
                show()
            }
    }

    @JvmOverloads
    fun showSecurityDialog(
        context: Context,
        message: String,
        isCritical: Boolean,
        onResponse: Consumer<Boolean>? = null
    ) {
        dialogQueue.add(SecurityDialogInfo(message, isCritical, onResponse?.let { consumer -> { value -> consumer.accept(value) } }))
        if (!isShowingDialog) {
            showNextDialog(context)
        }
    }

    // Configuration class to control security check behavior
    data class SecurityConfig(
        val rootCheck: SecurityCheckState = SecurityCheckState.ERROR,
        val developerOptionsCheck: SecurityCheckState = SecurityCheckState.ERROR,
        val malwareCheck: SecurityCheckState = SecurityCheckState.ERROR,
        val tamperingCheck: SecurityCheckState = SecurityCheckState.ERROR,
        val networkSecurityCheck: SecurityCheckState = SecurityCheckState.WARNING,
        val screenSharingCheck: SecurityCheckState = SecurityCheckState.WARNING,
        val appSpoofingCheck: SecurityCheckState = SecurityCheckState.WARNING,
        val keyloggerCheck: SecurityCheckState = SecurityCheckState.WARNING,
        val expectedPackageName: String? = null
    )

    @JvmField
    val DISABLED = SecurityCheckState.DISABLED

    @JvmField
    val WARNING = SecurityCheckState.WARNING

    @JvmField
    val ERROR = SecurityCheckState.ERROR

    enum class SecurityCheckState {
        DISABLED, WARNING, ERROR;

        companion object {
            @JvmStatic
            fun fromString(value: String): SecurityCheckState {
                return valueOf(value.uppercase())
            }
        }
    }

    // Check for rooted device
    fun checkRootStatus(): SecurityCheck {
        if (config.rootCheck == SecurityCheckState.DISABLED) {
            return SecurityCheck.Success
        }
        
        val rootBeer = RootUtil(context).isDeviceRooted
        return if (rootBeer) {
            if (config.rootCheck == SecurityCheckState.WARNING) {
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
        if (config.developerOptionsCheck == SecurityCheckState.DISABLED) {
            return SecurityCheck.Success
        }

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
            developerMode -> createDevOptionsResponse("Developer options are enabled.")
            usbDebugging -> createDevOptionsResponse("USB debugging is enabled.")
            mockLocation -> createDevOptionsResponse("Mock location is enabled.")
            isTimeManipulated(context) -> createDevOptionsResponse("Automatic time settings are disabled.")
            else -> SecurityCheck.Success
        }
    }

    private fun createDevOptionsResponse(message: String): SecurityCheck {
        return when (config.developerOptionsCheck) {
            SecurityCheckState.WARNING -> SecurityCheck.Warning("$message This may pose security risks.")
            SecurityCheckState.ERROR -> SecurityCheck.Critical("$message Please disable it to continue using the application.")
            SecurityCheckState.DISABLED -> SecurityCheck.Success
        }
    }

    private fun isTimeManipulated(context: Context): Boolean {
        try {
            val autoTime = Settings.Global.getInt(context.contentResolver, Settings.Global.AUTO_TIME)
            val autoTimeZone = Settings.Global.getInt(context.contentResolver, Settings.Global.AUTO_TIME_ZONE)
            return autoTime == 0 || autoTimeZone == 0
        } catch (e: Settings.SettingNotFoundException) {
            e.printStackTrace()
            return false
        }
    }

    // Check network security
    fun checkNetworkSecurity(): SecurityCheck {
        if (config.networkSecurityCheck == SecurityCheckState.DISABLED) {
            return SecurityCheck.Success
        }

        val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val network = connectivityManager.activeNetwork
        val capabilities = connectivityManager.getNetworkCapabilities(network)

        return when {
            capabilities == null -> createNetworkSecurityResponse("No active network connection")
            isVPNActive(context) -> createNetworkSecurityResponse(context.getString(R.string.vpn_warning))
            isProxySet(context) -> createNetworkSecurityResponse(context.getString(R.string.proxy_warning))
            !isWifiSecure(context) -> createNetworkSecurityResponse(context.getString(R.string.usecured_network_warning))
            else -> SecurityCheck.Success
        }
    }

    private fun createNetworkSecurityResponse(message: String): SecurityCheck {
        return when (config.networkSecurityCheck) {
            SecurityCheckState.WARNING -> SecurityCheck.Warning(message)
            SecurityCheckState.ERROR -> SecurityCheck.Critical(message)
            SecurityCheckState.DISABLED -> SecurityCheck.Success
        }
    }

    // Check for malware and tampering
    fun checkMalwareAndTampering(): SecurityCheck {
        if (config.malwareCheck == SecurityCheckState.DISABLED && 
            config.tamperingCheck == SecurityCheckState.DISABLED) {
            return SecurityCheck.Success
        }

        try {
            val packageInfo = context.packageManager.getPackageInfo(
                context.packageName,
                PackageManager.GET_SIGNATURES
            )
            
            val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                packageInfo.signingInfo?.apkContentsSigners
            } else {
                @Suppress("DEPRECATION")
                packageInfo.signatures
            }

            if (!verifySignature(signatures!!)) {
                return when (config.tamperingCheck) {
                    SecurityCheckState.WARNING -> SecurityCheck.Warning("Application signature verification failed. This may indicate tampering.")
                    SecurityCheckState.ERROR -> SecurityCheck.Critical("Application signature is not as expected. Please reinstall from official source.")
                    SecurityCheckState.DISABLED -> SecurityCheck.Success
                }
            }

            if (Settings.canDrawOverlays(context)) {
                return when (config.malwareCheck) {
                    SecurityCheckState.WARNING -> SecurityCheck.Warning("Screen overlay detected. This could pose security risks.")
                    SecurityCheckState.ERROR -> SecurityCheck.Critical("Screen overlay detected, which could be malicious.")
                    SecurityCheckState.DISABLED -> SecurityCheck.Success
                }
            }

            return SecurityCheck.Success
        } catch (e: Exception) {
            return when (config.malwareCheck) {
                SecurityCheckState.WARNING -> SecurityCheck.Warning("Security verification failed. This may pose risks.")
                SecurityCheckState.ERROR -> SecurityCheck.Critical("Security verification failed.")
                SecurityCheckState.DISABLED -> SecurityCheck.Success
            }
        }
    }

    // Check for screen mirroring and remote access
    fun checkScreenMirroring(): SecurityCheck {
        if (config.screenSharingCheck == SecurityCheckState.DISABLED) {
            return SecurityCheck.Success
        }

        val message = when {
            ScreenSharingDetector.isScreenSharingActive(context) -> context.getString(R.string.screen_sharing_warniong)
            ScreenSharingDetector.isScreenMirrored(context) -> context.getString(R.string.screen_mirroring_warniong)
            isScreenRecording() -> context.getString(R.string.screen_recording_warniong)
            else -> return SecurityCheck.Success
        }

        return when (config.screenSharingCheck) {
            SecurityCheckState.WARNING -> SecurityCheck.Warning(message)
            SecurityCheckState.ERROR -> SecurityCheck.Critical(message)
            SecurityCheckState.DISABLED -> SecurityCheck.Success
        }
    }

    // Check for app spoofing
    fun checkAppSpoofing(): SecurityCheck {
        if (config.appSpoofingCheck == SecurityCheckState.DISABLED) {
            return SecurityCheck.Success
        }

        val expectedPackage = config.expectedPackageName ?: ""
        val calculatedPackageName = context.packageName
        if (expectedPackage != calculatedPackageName) {
            Log.e("Security", "Application spoofing detected. Expected: $expectedPackage, Found: $calculatedPackageName")
            return when (config.appSpoofingCheck) {
                SecurityCheckState.WARNING -> SecurityCheck.Warning(context.getString(R.string.app_spoofing_warniong))
                SecurityCheckState.ERROR -> SecurityCheck.Critical(context.getString(R.string.app_spoofing_warniong))
                SecurityCheckState.DISABLED -> SecurityCheck.Success
            }
        }
        return SecurityCheck.Success
    }

    // Check for keylogger
    fun checkKeyLoggerDetection(): SecurityCheck {
        if (config.keyloggerCheck == SecurityCheckState.DISABLED) {
            return SecurityCheck.Success
        }

        if (KeyloggerDetection.isAccessibilityServiceEnabled(context)) {
            return when (config.keyloggerCheck) {
                SecurityCheckState.WARNING -> SecurityCheck.Warning(context.getString(R.string.accecibility_warniong))
                SecurityCheckState.ERROR -> SecurityCheck.Critical(context.getString(R.string.accecibility_warniong))
                SecurityCheckState.DISABLED -> SecurityCheck.Success
            }
        }
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
}
