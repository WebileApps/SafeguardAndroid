package com.webileapps.safeguard;

import android.Manifest;
import android.app.Activity;
import android.app.ActivityManager;
import android.app.AlertDialog;
import android.content.Context;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.media.projection.MediaProjectionManager;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.LinkProperties;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.telephony.PhoneStateListener;
import android.telephony.TelephonyCallback;
import android.telephony.TelephonyManager;
import android.util.Log;
import androidx.activity.ComponentActivity;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.core.content.ContextCompat;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

public class SecurityChecker {
    private final Context context;
    private final SecurityConfig config;
    private static final int PERMISSION_REQUEST_CODE = 1001;

    private final List<SecurityDialogInfo> dialogQueue = new ArrayList<>();
    private boolean isShowingDialog = false;

    private TelephonyManager telephonyManager;
    private PhoneStateListener phoneStateListener;
    private TelephonyCallback telephonyCallback;
    private ConnectivityManager connectivityManager;
    private ConnectivityManager.NetworkCallback networkCallback;
    private ComponentActivity activity;
    private Runnable permissionGrantedCallback;
    private ActivityResultLauncher<String> permissionLauncher;
    private Handler handler = new Handler(Looper.getMainLooper());

    public static class SecurityConfig {
        private final SecurityCheckState rootCheck;
        private final SecurityCheckState developerOptionsCheck;
        private final SecurityCheckState malwareCheck;
        private final SecurityCheckState tamperingCheck;
        private final SecurityCheckState appSpoofingCheck;
        private final SecurityCheckState networkSecurityCheck;
        private final SecurityCheckState screenSharingCheck;
        private final SecurityCheckState keyloggerCheck;
        private final SecurityCheckState appSignature;
        private final SecurityCheckState ongoingCallCheck;

        // Customizable dialog options with defaults
        private String criticalDialogTitle = "Security Error";
        private String warningDialogTitle = "Security Warning";
        private String criticalDialogPositiveButton = "Quit";
        private String warningDialogPositiveButton = "Continue Anyway";
        private String criticalDialogNegativeButton = null;
        private String warningDialogNegativeButton = null;

        public String getCriticalDialogTitle() { return criticalDialogTitle; }
        public String getWarningDialogTitle() { return warningDialogTitle; }
        public String getCriticalDialogPositiveButton() { return criticalDialogPositiveButton; }
        public String getWarningDialogPositiveButton() { return warningDialogPositiveButton; }
        public String getCriticalDialogNegativeButton() { return criticalDialogNegativeButton; }
        public String getWarningDialogNegativeButton() { return warningDialogNegativeButton; }
        private final String expectedPackageName;
        private final String expectedSignature;

        public SecurityConfig() {
            this(
                SecurityCheckState.ERROR,    // rootCheck
                SecurityCheckState.ERROR,    // developerOptionsCheck
                SecurityCheckState.ERROR,    // malwareCheck
                SecurityCheckState.ERROR,    // tamperingCheck
                SecurityCheckState.WARNING,  // appSpoofingCheck
                SecurityCheckState.WARNING,  // networkSecurityCheck
                SecurityCheckState.WARNING,  // screenSharingCheck
                SecurityCheckState.WARNING,  // keyloggerCheck
                SecurityCheckState.WARNING,  // appSignature
                SecurityCheckState.WARNING,  // ongoingCallCheck
                "",                         // expectedPackageName
                ""                          // expectedSignature
            );
        }

        public SecurityConfig(
            SecurityCheckState rootCheck,
            SecurityCheckState developerOptionsCheck,
            SecurityCheckState malwareCheck,
            SecurityCheckState tamperingCheck,
            SecurityCheckState appSpoofingCheck,
            SecurityCheckState networkSecurityCheck,
            SecurityCheckState screenSharingCheck,
            SecurityCheckState keyloggerCheck,
            SecurityCheckState appSignature,
            SecurityCheckState ongoingCallCheck,
            String expectedPackageName,
            String expectedSignature
        ) {
            this(rootCheck, developerOptionsCheck, malwareCheck, tamperingCheck, appSpoofingCheck, networkSecurityCheck,
                screenSharingCheck, keyloggerCheck, appSignature, ongoingCallCheck, expectedPackageName, expectedSignature,
                "Security Error", "Security Warning", "Quit", "Continue Anyway", null, null);
        }

        /**
         * Extended constructor to allow dialog customization at runtime.
         */
        public SecurityConfig(
            SecurityCheckState rootCheck,
            SecurityCheckState developerOptionsCheck,
            SecurityCheckState malwareCheck,
            SecurityCheckState tamperingCheck,
            SecurityCheckState appSpoofingCheck,
            SecurityCheckState networkSecurityCheck,
            SecurityCheckState screenSharingCheck,
            SecurityCheckState keyloggerCheck,
            SecurityCheckState appSignature,
            SecurityCheckState ongoingCallCheck,
            String expectedPackageName,
            String expectedSignature,
            String criticalDialogTitle,
            String warningDialogTitle,
            String criticalDialogPositiveButton,
            String warningDialogPositiveButton,
            String criticalDialogNegativeButton,
            String warningDialogNegativeButton
        ) {
            this.rootCheck = rootCheck;
            this.developerOptionsCheck = developerOptionsCheck;
            this.malwareCheck = malwareCheck;
            this.tamperingCheck = tamperingCheck;
            this.appSpoofingCheck = appSpoofingCheck;
            this.networkSecurityCheck = networkSecurityCheck;
            this.screenSharingCheck = screenSharingCheck;
            this.keyloggerCheck = keyloggerCheck;
            this.appSignature = appSignature;
            this.ongoingCallCheck = ongoingCallCheck;
            this.expectedPackageName = expectedPackageName;
            this.expectedSignature = expectedSignature;
            this.criticalDialogTitle = criticalDialogTitle;
            this.warningDialogTitle = warningDialogTitle;
            this.criticalDialogPositiveButton = criticalDialogPositiveButton;
            this.warningDialogPositiveButton = warningDialogPositiveButton;
            this.criticalDialogNegativeButton = criticalDialogNegativeButton;
            this.warningDialogNegativeButton = warningDialogNegativeButton;
        }

        // Getters
        public SecurityCheckState getRootCheck() { return rootCheck; }
        public SecurityCheckState getDeveloperOptionsCheck() { return developerOptionsCheck; }
        public SecurityCheckState getMalwareCheck() { return malwareCheck; }
        public SecurityCheckState getTamperingCheck() { return tamperingCheck; }
        public SecurityCheckState getAppSpoofingCheck() { return appSpoofingCheck; }
        public SecurityCheckState getNetworkSecurityCheck() { return networkSecurityCheck; }
        public SecurityCheckState getScreenSharingCheck() { return screenSharingCheck; }
        public SecurityCheckState getKeyloggerCheck() { return keyloggerCheck; }
        public SecurityCheckState getAppSignature() { return appSignature; }
        public SecurityCheckState getOngoingCallCheck() { return ongoingCallCheck; }
        public String getExpectedPackageName() { return expectedPackageName; }
        public String getExpectedSignature() { return expectedSignature; }
    }

    private static class SecurityDialogInfo {
        private final String message;
        private final boolean isCritical;
        private final Consumer<Boolean> onResponse;

        SecurityDialogInfo(String message, boolean isCritical, Consumer<Boolean> onResponse) {
            this.message = message;
            this.isCritical = isCritical;
            this.onResponse = onResponse;
        }
    }

    public enum SecurityCheckState {
        DISABLED, WARNING, ERROR;

        public static SecurityCheckState fromString(String value) {
            return valueOf(value.toUpperCase());
        }
    }

    public static abstract class SecurityCheck {
        public static class Success extends SecurityCheck {}
        public static class Warning extends SecurityCheck {
            public final String message;
            public Warning(String message) { this.message = message; }
        }
        public static class Critical extends SecurityCheck {
            public final String message;
            public Critical(String message) { this.message = message; }
        }
    }

    public SecurityChecker(Context context) {
        this(context, new SecurityConfig());
    }

    public SecurityChecker(Context context, SecurityConfig config) {
        this.context = context;
        this.config = config;

        if (config.getOngoingCallCheck() != SecurityCheckState.DISABLED) {
            initializeCallMonitoring();
        }
        if (config.getNetworkSecurityCheck() != SecurityCheckState.DISABLED) {
            initializeNetworkMonitoring();
        }
    }

    public void setupCallMonitoring(ComponentActivity activity, Runnable onPermissionDenied) {
        if (config.getOngoingCallCheck() == SecurityCheckState.DISABLED) {
            return;
        }

        int currentPermission = ContextCompat.checkSelfPermission(context, Manifest.permission.READ_PHONE_STATE);
        if (currentPermission != PackageManager.PERMISSION_GRANTED) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                if (activity.shouldShowRequestPermissionRationale(Manifest.permission.READ_PHONE_STATE)) {
                    new AlertDialog.Builder(activity)
                        .setTitle("Permission Required")
                        .setMessage("The app needs phone state permission to monitor calls for security purposes.")
                        .setPositiveButton("Grant", (dialog, which) -> {
                            requestPermission(activity, () -> initializeCallMonitoring());
                        })
                        .setNegativeButton("Deny", (dialog, which) -> {
                            dialog.dismiss();
                            if (onPermissionDenied != null) {
                                onPermissionDenied.run();
                            }
                        })
                        .show();
                } else {
                    requestPermission(activity, () -> initializeCallMonitoring());
                }
            }
            return;
        }

        initializeCallMonitoring();
    }

    private void requestPermission(ComponentActivity activity, Runnable onGranted) {
        activity.registerForActivityResult(
            new ActivityResultContracts.RequestPermission(),
            isGranted -> {
                if (isGranted) {
                    onGranted.run();
                }
            }
        ).launch(Manifest.permission.READ_PHONE_STATE);
    }

    private void initializeCallMonitoring() {
        try {
            telephonyManager = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                setupModernCallMonitoring();
            } else {
                setupLegacyCallMonitoring();
            }
        } catch (SecurityException e) {
            Log.e("SecurityChecker", "Failed to initialize call monitoring", e);
        }
    }

    @androidx.annotation.RequiresApi(Build.VERSION_CODES.S)
    private void setupModernCallMonitoring() {
        try {
            CallStateListener callStateListener = new CallStateListener();
            telephonyManager.registerTelephonyCallback(
                context.getMainExecutor(),
                callStateListener
            );
            telephonyCallback = callStateListener;
        } catch (SecurityException ignored) {
        }
    }

    @SuppressWarnings("deprecation")
    private void setupLegacyCallMonitoring() {
        try {
            phoneStateListener = new PhoneStateListener() {
                @Override
                public void onCallStateChanged(int state, String phoneNumber) {
                    handleCallStateChange(state);
                }
            };
            telephonyManager.listen(phoneStateListener, PhoneStateListener.LISTEN_CALL_STATE);
        } catch (SecurityException ignored) {
        }
    }

    @androidx.annotation.RequiresApi(Build.VERSION_CODES.S)
    private class CallStateListener extends TelephonyCallback implements TelephonyCallback.CallStateListener {
        @Override
        public void onCallStateChanged(int state) {
            handleCallStateChange(state);
        }
    }

    private void handleCallStateChange(int state) {
        if (config.getOngoingCallCheck() == SecurityCheckState.DISABLED) return;

        boolean isCallActive = state == TelephonyManager.CALL_STATE_OFFHOOK || 
                             state == TelephonyManager.CALL_STATE_RINGING;

        if (isCallActive && state ==2) {
            switch (config.getOngoingCallCheck()) {
                case WARNING:
                    showSecurityDialog(
                        context,
                        context.getString(R.string.ongoing_call_warning),
                        false,
                        null
                    );
                    break;
                case ERROR:
                    showSecurityDialog(
                        context,
                        context.getString(R.string.ongoing_call_critical),
                        true,
                        null
                    );
                    break;
            }
        }
    }

    private void showNextDialog(Context context) {
        if (isShowingDialog || dialogQueue.isEmpty()) return;

        // Ensure this runs on UI thread
        new Handler(Looper.getMainLooper()).post(() -> {
            if (!(context instanceof Activity)) {
                return;
            }

            Activity activity = (Activity) context;

            // Check if activity is in valid state
            if (activity.isFinishing() || activity.isDestroyed()) {
                return;
            }
            if (dialogQueue.isEmpty()) {
                isShowingDialog = false;
                return;
            }
            isShowingDialog = true;
            SecurityDialogInfo dialogInfo = dialogQueue.remove(0);

            String title = dialogInfo.isCritical ? config.getCriticalDialogTitle() : config.getWarningDialogTitle();
            String positiveButton = dialogInfo.isCritical ? config.getCriticalDialogPositiveButton() : config.getWarningDialogPositiveButton();
          //  String negativeButton = dialogInfo.isCritical ? config.getCriticalDialogNegativeButton() : config.getWarningDialogNegativeButton();

            AlertDialog.Builder builder = new AlertDialog.Builder(activity)
                    .setTitle(title)
                    .setMessage(dialogInfo.message)
                    .setPositiveButton(positiveButton, (dialogInterface, which) -> {
                        dialogInterface.dismiss();
                        if (dialogInfo.isCritical) {
                            System.exit(0);
                        } else {
                            if (dialogInfo.onResponse != null) {
                                dialogInfo.onResponse.accept(true);
                            }
                            isShowingDialog = false;
                            showNextDialog(activity);
                        }
                    })
                    .setCancelable(!dialogInfo.isCritical);

           /* if (negativeButton != null && !negativeButton.isEmpty()) {
                builder.setNegativeButton(negativeButton, (dialogInterface, which) -> {
                    dialogInterface.dismiss();
                    isShowingDialog = false;
                    showNextDialog(activity);
                });
            }*/

            AlertDialog dialog = builder.create();

            dialog.setOnDismissListener(dialogInterface -> {
                if (!dialogInfo.isCritical) {
                    isShowingDialog = false;
                    showNextDialog(activity);
                }
            });

            dialog.show();
        });
    }

    public void showSecurityDialog(Context context, String message, boolean isCritical, Consumer<Boolean> onResponse) {
        dialogQueue.add(new SecurityDialogInfo(message, isCritical, onResponse));
        if (!isShowingDialog) {
            showNextDialog(context);
        }
    }

    private void initializeNetworkMonitoring() {
        Log.d("SecurityChecker", "Initializing network monitoring");
        connectivityManager = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        
        networkCallback = new ConnectivityManager.NetworkCallback() {
            @Override
            public void onAvailable(Network network) {
                Log.d("SecurityChecker", "Network became available: " + network);
                handleNetworkChange();
            }

            @Override
            public void onLost(Network network) {
                Log.d("SecurityChecker", "Network was lost: " + network);
                handleNetworkChange();
            }

            @Override
            public void onCapabilitiesChanged(Network network, NetworkCapabilities networkCapabilities) {
                Log.d("SecurityChecker", "Network capabilities changed: " + 
                    networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET));
                handleNetworkChange();
            }

            @Override
            public void onLinkPropertiesChanged(Network network, LinkProperties linkProperties) {
                Log.d("SecurityChecker", "Network properties changed: " + linkProperties.getHttpProxy());
                handleNetworkChange();
            }
        };

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            Log.d("SecurityChecker", "Registering default network callback");
            connectivityManager.registerDefaultNetworkCallback(networkCallback);
        } else {
            Log.d("SecurityChecker", "Registering network callback with builder");
            NetworkRequest.Builder builder = new NetworkRequest.Builder();
            connectivityManager.registerNetworkCallback(builder.build(), networkCallback);
        }
    }

    private void handleNetworkChange() {
        if (config.getNetworkSecurityCheck() == SecurityCheckState.DISABLED) {
            Log.d("SecurityChecker", "Network security check is disabled");
            return;
        }

        SecurityCheck networkCheck = checkNetworkSecurity();
        Log.d("SecurityChecker", "Network security check result: " + networkCheck);
        
        if (!(networkCheck instanceof SecurityCheck.Success)) {
            if (networkCheck instanceof SecurityCheck.Warning) {
                SecurityCheck.Warning warning = (SecurityCheck.Warning) networkCheck;
                Log.d("SecurityChecker", "Network security warning: " + warning.message);
                showSecurityDialog(context, warning.message, false, null);
            } else if (networkCheck instanceof SecurityCheck.Critical) {
                SecurityCheck.Critical critical = (SecurityCheck.Critical) networkCheck;
                Log.d("SecurityChecker", "Network security critical: " + critical.message);
                showSecurityDialog(context, critical.message, true, null);
            }
        }
    }

    public SecurityCheck checkRootStatus() {
        if (config.getRootCheck() == SecurityCheckState.DISABLED) {
            return new SecurityCheck.Success();
        }
        
        boolean isRooted = new RootUtil(context).isDeviceRooted();
        if ( RootUtil.isBootStateUntrusted()) {
            if (config.getRootCheck() == SecurityCheckState.WARNING) {
                return new SecurityCheck.Warning(context.getString(R.string.rooted_warning));
            } else {
                return new SecurityCheck.Critical(context.getString(R.string.rooted_critical));
            }
        }
        return new SecurityCheck.Success();
    }

    public SecurityCheck checkDeveloperOptions() {
        if (config.getDeveloperOptionsCheck() == SecurityCheckState.DISABLED) {
            return new SecurityCheck.Success();
        }

        try {
            boolean developerMode = Settings.Global.getInt(
                    context.getContentResolver(),
                    Settings.Global.DEVELOPMENT_SETTINGS_ENABLED
            ) != 0;

            if (developerMode) {
                return createDevOptionsResponse(context.getString(R.string.developer_options_warning));
            }
        } catch (Settings.SettingNotFoundException ignored) {
        }

        try {
            boolean usbDebugging = Settings.Global.getInt(
                    context.getContentResolver(),
                    Settings.Global.ADB_ENABLED
            ) != 0;
            if (usbDebugging) {
                return createDevOptionsResponse("USB debugging is enabled.");
            }
        } catch (Settings.SettingNotFoundException ignored) {
        }

        try {
            boolean mockLocation = !"0".equals(Settings.Secure.getString(
                context.getContentResolver(),
                Settings.Secure.ALLOW_MOCK_LOCATION
            ));

            if (mockLocation) {
                return createDevOptionsResponse("Mock location is enabled.");
            } else if (isTimeManipulated()) {
                return createDevOptionsResponse(context.getString(R.string.auto_time_warning));
            }
        } catch (Exception ignored) {
        }

        return new SecurityCheck.Success();
    }

    private SecurityCheck createDevOptionsResponse(String message) {
        switch (config.getDeveloperOptionsCheck()) {
            case WARNING:
                return new SecurityCheck.Warning(message);
            case ERROR:
                return new SecurityCheck.Critical(message);
            default:
                return new SecurityCheck.Success();
        }
    }

    private boolean isTimeManipulated() {
        try {
            int autoTime = Settings.Global.getInt(context.getContentResolver(), Settings.Global.AUTO_TIME);
            int autoTimeZone = Settings.Global.getInt(context.getContentResolver(), Settings.Global.AUTO_TIME_ZONE);
            return autoTime == 0 || autoTimeZone == 0;
        } catch (Settings.SettingNotFoundException e) {
            return false;
        }
    }

    public SecurityCheck checkNetworkSecurity() {
        if (config.getNetworkSecurityCheck() == SecurityCheckState.DISABLED) {
            return new SecurityCheck.Success();
        }

        ConnectivityManager connectivityManager = 
            (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        Network network = connectivityManager.getActiveNetwork();
        NetworkCapabilities capabilities = connectivityManager.getNetworkCapabilities(network);

        if (capabilities == null) {
            return new SecurityCheck.Success();
        } else if (NetworkUtils.isVPNActive(context)) {
            return createNetworkSecurityResponse(context.getString(R.string.vpn_warning));
        } else if (NetworkUtils.isProxySet(context)) {
            return createNetworkSecurityResponse(context.getString(R.string.proxy_warning));
        } else if (!NetworkUtils.isWifiSecure(context)) {
            return createNetworkSecurityResponse(context.getString(R.string.unsecured_network_warning));
        }else if (ADBWireless.adbWirelessCheck(context)) {
            return createNetworkSecurityResponse(context.getString(R.string.unsecured_network_warning));
        }
        
        return new SecurityCheck.Success();
    }

    private SecurityCheck createNetworkSecurityResponse(String message) {
        switch (config.getNetworkSecurityCheck()) {
            case WARNING:
                return new SecurityCheck.Warning(message);
            case ERROR:
                return new SecurityCheck.Critical(message);
            default:
                return new SecurityCheck.Success();
        }
    }

    public SecurityCheck appSignatureCompare() {
        if (!new SignatureComparison().isAppSignatureValid(context, config.getExpectedSignature())) {
            switch (config.getAppSignature()) {
                case WARNING:
                    return new SecurityCheck.Warning(context.getString(R.string.app_signature_warning));
                case ERROR:
                    return new SecurityCheck.Critical(context.getString(R.string.app_signature_critical));
                default:
                    return new SecurityCheck.Success();
            }
        }
        return new SecurityCheck.Success();
    }

    public SecurityCheck checkMalwareAndTampering() {
        if (config.getMalwareCheck() == SecurityCheckState.DISABLED && 
            config.getTamperingCheck() == SecurityCheckState.DISABLED) {
            return new SecurityCheck.Success();
        }

        try {
            if (Settings.canDrawOverlays(context)) {
                switch (config.getMalwareCheck()) {
                    case WARNING:
                        return new SecurityCheck.Warning("Screen overlay detected. This could pose security risks.");
                    case ERROR:
                        return new SecurityCheck.Critical("Screen overlay detected, which could be malicious.");
                    default:
                        return new SecurityCheck.Success();
                }
            }
            return new SecurityCheck.Success();
        } catch (Exception e) {
            switch (config.getMalwareCheck()) {
                case WARNING:
                    return new SecurityCheck.Warning("Security verification failed. This may pose risks.");
                case ERROR:
                    return new SecurityCheck.Critical("Security verification failed.");
                default:
                    return new SecurityCheck.Success();
            }
        }
    }

    public SecurityCheck checkScreenMirroring() {
        if (config.getScreenSharingCheck() == SecurityCheckState.DISABLED) {
            return new SecurityCheck.Success();
        }

        String message;
        if (ScreenSharingDetector.isScreenSharingActive(context)) {
            message = context.getString(R.string.screen_sharing_warning);
        } else if (ScreenSharingDetector.isScreenMirrored(context)) {
            message = context.getString(R.string.screen_mirroring_warning);
        } else if (isScreenRecording()) {
            message = context.getString(R.string.screen_recording_warning);
        } else {
            return new SecurityCheck.Success();
        }

        switch (config.getScreenSharingCheck()) {
            case WARNING:
                return new SecurityCheck.Warning(message);
            case ERROR:
                return new SecurityCheck.Critical(message);
            default:
                return new SecurityCheck.Success();
        }
    }

    public SecurityCheck checkAppSpoofing() {
        if (config.getAppSpoofingCheck() == SecurityCheckState.DISABLED) {
            return new SecurityCheck.Success();
        }

        String expectedPackage = config.getExpectedPackageName();
        String calculatedPackageName = context.getPackageName();
        if (!expectedPackage.equals(calculatedPackageName)) {
            Log.e("Security", "Application spoofing detected. Expected: " + expectedPackage + 
                            ", Found: " + calculatedPackageName);
            switch (config.getAppSpoofingCheck()) {
                case WARNING:
                    return new SecurityCheck.Warning(context.getString(R.string.app_spoofing_warning));
                case ERROR:
                    return new SecurityCheck.Critical(context.getString(R.string.app_spoofing_warning));
                default:
                    return new SecurityCheck.Success();
            }
        }
        return new SecurityCheck.Success();
    }

    public SecurityCheck checkKeyLoggerDetection() {
        if (config.getKeyloggerCheck() == SecurityCheckState.DISABLED) {
            return new SecurityCheck.Success();
        }

        if (KeyloggerDetection.isAccessibilityServiceEnabled(context)) {
            switch (config.getKeyloggerCheck()) {
                case WARNING:
                    return new SecurityCheck.Warning(context.getString(R.string.accessibility_warning));
                case ERROR:
                    return new SecurityCheck.Critical(context.getString(R.string.accessibility_warning));
                default:
                    return new SecurityCheck.Success();
            }
        }
        return new SecurityCheck.Success();
    }

    private boolean isScreenRecording() {
        // This is a simplified check. In production, you'd want more sophisticated detection
        MediaProjectionManager projectionManager = 
            (MediaProjectionManager) context.getSystemService(Context.MEDIA_PROJECTION_SERVICE);
        return false; // Placeholder - actual implementation would be more complex
    }

    private boolean verifySignature(Signature[] signatures) {
        // In production, you would compare against your known good signature
        return signatures.length > 0;
    }

    public void runSecurityChecks() {
        // Check root status
        SecurityCheck rootCheck = checkRootStatus();
        showDialog(rootCheck);

        // Check developer options
        SecurityCheck devCheck = checkDeveloperOptions();
        showDialog(devCheck);

        // Check malware
        SecurityCheck malwareCheck = checkMalwareAndTampering();
        showDialog(malwareCheck);

        // Check network security
        SecurityCheck networkCheck = checkNetworkSecurity();
        showDialog(networkCheck);

        // Check screen mirroring
        SecurityCheck screenCheck = checkScreenMirroring();
        showDialog(screenCheck);

        // Check app spoofing
        SecurityCheck spoofingCheck = checkAppSpoofing();
        showDialog(spoofingCheck);

        // Check keylogger
        SecurityCheck keyloggerCheck = checkKeyLoggerDetection();
        showDialog(keyloggerCheck);

        SecurityCheck signatureCheck = appSignatureCompare();
        showDialog(signatureCheck);
    }

    private void showDialog(SecurityCheck result) {
        if (result instanceof SecurityCheck.Critical) {
            SecurityCheck.Critical critical = (SecurityCheck.Critical) result;
            SecurityConfigManager.getSecurityChecker().showSecurityDialog(
                context, 
                critical.message, 
                true,
                null
            );
        } else if (result instanceof SecurityCheck.Warning) {
            SecurityCheck.Warning warning = (SecurityCheck.Warning) result;
            SecurityConfigManager.getSecurityChecker().showSecurityDialog(
                context, 
                warning.message, 
                false,
                userAcknowledged -> {}
            );
        }
    }

    public void cleanup() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            if (telephonyCallback != null) {
                telephonyManager.unregisterTelephonyCallback(telephonyCallback);
            }
        } else {
            if (phoneStateListener != null) {
                telephonyManager.listen(phoneStateListener, PhoneStateListener.LISTEN_NONE);
            }
        }
        
        if (networkCallback != null) {
            connectivityManager.unregisterNetworkCallback(networkCallback);
        }

        telephonyCallback = null;
        phoneStateListener = null;
        telephonyManager = null;
        networkCallback = null;
        connectivityManager = null;
    }

    public String generateFileChecksum(File file, String algorithm) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
            InputStream inputStream = new FileInputStream(file);
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                messageDigest.update(buffer, 0, bytesRead);
            }
            inputStream.close();

            byte[] hashBytes = messageDigest.digest();
            StringBuilder hexString = new StringBuilder();
            for (byte hashByte : hashBytes) {
                hexString.append(String.format("%02x", hashByte));
            }
            return hexString.toString();
        } catch (Exception e) {
            return null;
        }
    }

    public boolean validateFileChecksum(File file, String expectedChecksum, String algorithm) {
        String generatedChecksum = generateFileChecksum(file, algorithm);
        return generatedChecksum != null && generatedChecksum.equalsIgnoreCase(expectedChecksum);
    }

    public void checkFileIntegrity(String filePath, String expectedChecksum) {
        File file = new File(filePath);

        if (file.exists()) {
            boolean isValid = validateFileChecksum(file, expectedChecksum, "SHA-256");
            if (isValid) {
                Log.d("ChecksumValidation", "File is valid! Checksum matches.");
            } else {
                Log.e("ChecksumValidation", "File checksum mismatch! Possible tampering detected.");
            }
        } else {
            Log.e("ChecksumValidation", "File does not exist: " + filePath);
        }
    }

    public void startFridaDetection(){

        handler.post(new Runnable() {
            @Override
            public void run() {
                FridaDetection fridaDetection = new FridaDetection(context);
                if(fridaDetection.detectFridaDebugging()||HookingFrameworkDetection.isHookingDetected(context) || ParallelAppPrevention.isSecondSpaceAvailable(context)){
                    exitApp();
                }
                handler.postDelayed(this,5000);
            }
        });
    }

    public void exitApp(){
        ActivityManager activityManager= (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
        if (activityManager != null) {
            for (ActivityManager.AppTask task : activityManager.getAppTasks()) {
                task.finishAndRemoveTask(); // Finish and remove each task
            }
        }
        System.exit(0);
    }

}
