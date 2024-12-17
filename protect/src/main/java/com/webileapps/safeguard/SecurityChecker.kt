package com.webileapps.safeguard

import ScreenSharingDetector
import android.Manifest
import android.app.AlertDialog
import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.media.projection.MediaProjectionManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.LinkProperties
import android.os.Build
import android.provider.Settings
import android.telephony.PhoneStateListener
import android.telephony.TelephonyCallback
import android.telephony.TelephonyManager
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import com.webileapps.safeguard.NetworkUtils.isProxySet
import com.webileapps.safeguard.NetworkUtils.isVPNActive
import com.webileapps.safeguard.NetworkUtils.isWifiSecure
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

    private var telephonyManager: TelephonyManager? = null
    private var phoneStateListener: PhoneStateListener? = null
    private var telephonyCallback: TelephonyCallback? = null
    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    companion object {
        private const val PERMISSION_REQUEST_CODE = 1001
    }

    private var activity: ComponentActivity? = null
    private var permissionGrantedCallback: (() -> Unit)? = null
    private val permissionLauncher = activity?.registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { isGranted ->
        if (isGranted) {
            permissionGrantedCallback?.invoke()
        }
    }

    init {
        if (config.ongoingCallCheck != SecurityCheckState.DISABLED) {
            initializeCallMonitoring()
        }
        if (config.networkSecurityCheck != SecurityCheckState.DISABLED) {
            initializeNetworkMonitoring()
        }
    }

    /**
     * Sets up call monitoring with runtime permission handling.
     * This should be called from an Activity context when the app starts or resumes.
     * 
     * @param activity The activity to use for permission requests
     * @param onPermissionDenied Optional callback for when permission is denied
     */
    fun setupCallMonitoring(
        activity: ComponentActivity,
        onPermissionDenied: (() -> Unit)? = null
    ) {
        if (config.ongoingCallCheck == SecurityCheckState.DISABLED) {
            return
        }

        val currentPermission = ContextCompat.checkSelfPermission(context, Manifest.permission.READ_PHONE_STATE)
        if (currentPermission != PackageManager.PERMISSION_GRANTED) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                if (activity.shouldShowRequestPermissionRationale(Manifest.permission.READ_PHONE_STATE)) {
                    // Show rationale dialog
                    AlertDialog.Builder(activity)
                        .setTitle("Permission Required")
                        .setMessage("The app needs phone state permission to monitor calls for security purposes.")
                        .setPositiveButton("Grant") { _, _ ->
                            requestPermission(activity) {
                                initializeCallMonitoring()
                            }
                        }
                        .setNegativeButton("Deny") { dialog, _ ->
                            dialog.dismiss()
                            onPermissionDenied?.invoke()
                        }
                        .show()
                } else {
                    requestPermission(activity) {
                        initializeCallMonitoring()
                    }
                }
            }
            return
        }

        initializeCallMonitoring()
    }

    private fun requestPermission(activity: ComponentActivity, onGranted: () -> Unit) {
        activity.registerForActivityResult(
            ActivityResultContracts.RequestPermission()
        ) { isGranted ->
            if (isGranted) {
                onGranted()
            }
        }.launch(Manifest.permission.READ_PHONE_STATE)
    }

    private fun initializeCallMonitoring() {
        try {
            telephonyManager = context.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                // For API 31 and above
                setupModernCallMonitoring()
            } else {
                // For API 30 and below
                setupLegacyCallMonitoring()
            }
        } catch (e: SecurityException) {
            Log.e("SecurityChecker", "Failed to initialize call monitoring", e)
        }
    }

    @androidx.annotation.RequiresApi(Build.VERSION_CODES.S)
    private fun setupModernCallMonitoring() {
        try {
            telephonyCallback = object : TelephonyCallback(), TelephonyCallback.CallStateListener {
                override fun onCallStateChanged(state: Int) {
                    handleCallStateChange(state)
                }
            }
            telephonyManager?.registerTelephonyCallback(
                context.mainExecutor,
                telephonyCallback as TelephonyCallback
            )
        } catch (e: SecurityException) {
            // Handle permission denial
            e.printStackTrace()
        }
    }

    @Suppress("DEPRECATION")
    private fun setupLegacyCallMonitoring() {
        try {
            phoneStateListener = object : PhoneStateListener() {
                override fun onCallStateChanged(state: Int, phoneNumber: String?) {
                    handleCallStateChange(state)
                }
            }
            telephonyManager?.listen(phoneStateListener, PhoneStateListener.LISTEN_CALL_STATE)
        } catch (e: SecurityException) {
            // Handle permission denial
            e.printStackTrace()
        }
    }

    private fun handleCallStateChange(state: Int) {
        if (config.ongoingCallCheck == SecurityCheckState.DISABLED) return

        val isCallActive = when (state) {
            TelephonyManager.CALL_STATE_OFFHOOK, 
            TelephonyManager.CALL_STATE_RINGING -> true
            else -> false
        }

        if (isCallActive) {
            when (config.ongoingCallCheck) {
                SecurityCheckState.WARNING ->
                    showSecurityDialog(
                        context,
                        context.getString(R.string.ongoing_call_warning),
                        false
                    )
                SecurityCheckState.ERROR ->
                    showSecurityDialog(
                        context,
                        context.getString(R.string.ongoing_call_critical),
                        true
                    )
                else -> { /* Do nothing for DISABLED */ }
            }
        }
    }

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

    private fun initializeNetworkMonitoring() {
        Log.d("SecurityChecker", "Initializing network monitoring")
        connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        
        networkCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                Log.d("SecurityChecker", "Network became available: $network")
                handleNetworkChange()
            }

            override fun onLost(network: Network) {
                Log.d("SecurityChecker", "Network was lost: $network")
                handleNetworkChange()
            }

            override fun onCapabilitiesChanged(
                network: Network,
                networkCapabilities: NetworkCapabilities
            ) {
                Log.d("SecurityChecker", "Network capabilities changed: ${networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)}")
                handleNetworkChange()
            }

            override fun onLinkPropertiesChanged(
                network: Network,
                linkProperties: LinkProperties
            ) {
                Log.d("SecurityChecker", "Network properties changed: ${linkProperties.httpProxy}")
                handleNetworkChange()
            }
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            Log.d("SecurityChecker", "Registering default network callback")
            connectivityManager?.registerDefaultNetworkCallback(networkCallback!!)
        } else {
            Log.d("SecurityChecker", "Registering network callback with builder")
            val builder = NetworkRequest.Builder()
            connectivityManager?.registerNetworkCallback(builder.build(), networkCallback!!)
        }
    }

    private fun handleNetworkChange() {
        if (config.networkSecurityCheck == SecurityCheckState.DISABLED) {
            Log.d("SecurityChecker", "Network security check is disabled")
            return
        }

        val networkCheck = checkNetworkSecurity()
        Log.d("SecurityChecker", "Network security check result: $networkCheck")
        
        if (networkCheck !is SecurityCheck.Success) {
            when (networkCheck) {
                is SecurityCheck.Warning -> {
                    Log.d("SecurityChecker", "Network security warning: ${networkCheck.message}")
                    showSecurityDialog(
                        context,
                        networkCheck.message,
                        false
                    )
                }
                is SecurityCheck.Critical -> {
                    Log.d("SecurityChecker", "Network security critical: ${networkCheck.message}")
                    showSecurityDialog(
                        context,
                        networkCheck.message,
                        true
                    )
                }
                else -> { /* Do nothing for Success */ }
            }
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
        val appSignature: SecurityCheckState = SecurityCheckState.WARNING,
        val ongoingCallCheck: SecurityCheckState = SecurityCheckState.WARNING,
        val expectedPackageName: String = "",
        val expectedSignature: String = ""
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

    fun appSignatureCompare(): SecurityCheck {
        if(!SignatureComparison().isAppSignatureValid(context, config.expectedSignature)) {
            return when (config.appSignature) {
                SecurityCheckState.WARNING -> SecurityCheck.Warning(context.getString(R.string.app_signature_warning))
                SecurityCheckState.ERROR -> SecurityCheck.Critical(context.getString(R.string.app_signature_critical))
                SecurityCheckState.DISABLED -> SecurityCheck.Success
            }
        }
        return  SecurityCheck.Success
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
            ScreenSharingDetector.isScreenSharingActive(context) -> context.getString(R.string.screen_sharing_warning)
            ScreenSharingDetector.isScreenMirrored(context) -> context.getString(R.string.screen_mirroring_warning)
            isScreenRecording() -> context.getString(R.string.screen_recording_warning)
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
                SecurityCheckState.WARNING -> SecurityCheck.Warning(context.getString(R.string.app_spoofing_warning))
                SecurityCheckState.ERROR -> SecurityCheck.Critical(context.getString(R.string.app_spoofing_warning))
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
                SecurityCheckState.WARNING -> SecurityCheck.Warning(context.getString(R.string.accessibility_warning))
                SecurityCheckState.ERROR -> SecurityCheck.Critical(context.getString(R.string.accessibility_warning))
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

    fun runSecurityChecks() {
        // Check root status
        val rootCheck = checkRootStatus()
        if (rootCheck !is SecurityCheck.Success) {
            showSecurityDialog(
                context,
                "Root Access Detected",
                rootCheck is SecurityCheck.Critical
            )
        }

        // Check developer options
        val devCheck = checkDeveloperOptions()
        if (devCheck !is SecurityCheck.Success) {
            showSecurityDialog(
                context,
                "Developer Options Enabled",
                devCheck is SecurityCheck.Critical
            )
        }

        // Check malware
        val malwareCheck = checkMalwareAndTampering()
        if (malwareCheck !is SecurityCheck.Success) {
            showSecurityDialog(
                context,
                "Malware Detected",
                malwareCheck is SecurityCheck.Critical
            )
        }

        // Check network security
        val networkCheck = checkNetworkSecurity()
        if (networkCheck !is SecurityCheck.Success) {
            showSecurityDialog(
                context,
                "Network Security Issue",
                networkCheck is SecurityCheck.Critical
            )
        }

        // Check screen mirroring
        val screenCheck = checkScreenMirroring()
        if (screenCheck !is SecurityCheck.Success) {
            showSecurityDialog(
                context,
                "Screen Mirroring Detected",
                screenCheck is SecurityCheck.Critical
            )
        }

        // Check app spoofing
        val spoofingCheck = checkAppSpoofing()
        if (spoofingCheck !is SecurityCheck.Success) {
            showSecurityDialog(
                context,
                "App Spoofing Detected",
                spoofingCheck is SecurityCheck.Critical
            )
        }

        // Check keylogger
        val keyloggerCheck = checkKeyLoggerDetection()
        if (keyloggerCheck !is SecurityCheck.Success) {
            showSecurityDialog(
                context,
                "Keylogger Detected",
                keyloggerCheck is SecurityCheck.Critical
            )
        }

        val result = appSignatureCompare()
        if (result !is SecurityCheck.Success) {
            showSecurityDialog(
                context,
                "App Signature Detected",
                keyloggerCheck is SecurityCheck.Critical
            )
        }

    }

    fun cleanup() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            telephonyCallback?.let { callback ->
                telephonyManager?.unregisterTelephonyCallback(callback)
            }
        } else {
            @Suppress("DEPRECATION")
            phoneStateListener?.let { listener ->
                telephonyManager?.listen(listener, PhoneStateListener.LISTEN_NONE)
            }
        }
        
        networkCallback?.let { callback ->
            connectivityManager?.unregisterNetworkCallback(callback)
        }

        telephonyCallback = null
        phoneStateListener = null
        telephonyManager = null
        networkCallback = null
        connectivityManager = null
    }
}
