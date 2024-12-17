package com.webileapps.safeguard.cordova;

import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaWebView;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import android.content.Context;
import android.util.Log;

import com.webileapps.safeguard.SecurityChecker;
import com.webileapps.safeguard.SecurityConfigManager;

import java.util.function.Consumer;

public class SafeguardPlugin extends CordovaPlugin {
    private static final String TAG = "SafeguardPlugin";
    private CallbackContext securityCheckCallback;
    private SecurityChecker securityChecker;

    @Override
    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        super.initialize(cordova, webView);
        
        // Get preferences from config.xml
        String rootCheckState = getSecurityCheckState("ROOT_CHECK_STATE", "ERROR");
        String devOptionsCheckState = getSecurityCheckState("DEVELOPER_OPTIONS_CHECK_STATE", "WARNING");
        String malwareCheckState = getSecurityCheckState("MALWARE_CHECK_STATE", "WARNING");
        String tamperingCheckState = getSecurityCheckState("TAMPERING_CHECK_STATE", "WARNING");
        String networkSecurityCheckState = getSecurityCheckState("NETWORK_SECURITY_CHECK_STATE", "WARNING");
        String screenSharingCheckState = getSecurityCheckState("SCREEN_SHARING_CHECK_STATE", "WARNING");
        String appSpoofingCheckState = getSecurityCheckState("APP_SPOOFING_CHECK_STATE", "WARNING");
        String keyloggerCheckState = getSecurityCheckState("KEYLOGGER_CHECK_STATE", "WARNING");
        String ongoingCallCheckState = getSecurityCheckState("ONGOING_CALL_CHECK_STATE", "WARNING");
        String certificateMatchingCheckState = getSecurityCheckState("CERTIFICATE_MATCHING_CHECK_STATE", "WARNING");
        String expectedPackageName = preferences.getString("EXPECTED_PACKAGE_NAME", cordova.getActivity().getPackageName());
        String expectedCertificateHash = preferences.getString("EXPECTED_CERTIFICATE_HASH", "");

        // Initialize SecurityConfigManager with the configuration from config.xml
        SecurityConfigManager.INSTANCE.initialize(
            cordova.getContext(),
            new SecurityChecker.SecurityConfig(
                SecurityChecker.SecurityCheckState.fromString(rootCheckState),
                SecurityChecker.SecurityCheckState.fromString(devOptionsCheckState),
                SecurityChecker.SecurityCheckState.fromString(malwareCheckState),
                SecurityChecker.SecurityCheckState.fromString(tamperingCheckState),
                SecurityChecker.SecurityCheckState.fromString(networkSecurityCheckState),
                SecurityChecker.SecurityCheckState.fromString(screenSharingCheckState),
                SecurityChecker.SecurityCheckState.fromString(appSpoofingCheckState),
                SecurityChecker.SecurityCheckState.fromString(keyloggerCheckState),
                SecurityChecker.SecurityCheckState.fromString(certificateMatchingCheckState),
                SecurityChecker.SecurityCheckState.fromString(ongoingCallCheckState),
                expectedPackageName,
                expectedCertificateHash
            )
        );
        
        // Get the SecurityChecker instance
        securityChecker = SecurityConfigManager.INSTANCE.getSecurityChecker();

        securityChecker.setupCallMonitoring(cordova.getActivity(), () -> {
            return null;
        });
    }

    @Override
    public void onResume(boolean multitasking) {
        super.onResume(multitasking);
        cordova.getActivity().runOnUiThread(() -> {
            securityChecker.runSecurityChecks();
        });
    }

    private String getSecurityCheckState(String preferenceName, String defaultValue) {
        String value = preferences.getString(preferenceName, defaultValue);
        // Validate that the value is a valid SecurityCheckState
        try {
            SecurityChecker.SecurityCheckState.fromString(value);
            return value;
        } catch (IllegalArgumentException e) {
            Log.w(TAG, "Invalid security check state for " + preferenceName + ": " + value + ". Using default: " + defaultValue);
            return defaultValue;
        }
    }

    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
        Context context = cordova.getContext();

        switch (action) {
            case "checkRoot":
                cordova.getThreadPool().execute(() -> {
                    checkRoot(context, callbackContext);
                });
                return true;
            case "checkDeveloperOptions":
                cordova.getThreadPool().execute(() -> {
                    checkDeveloperOptions(context, callbackContext);
                });
                return true;
            case "checkMalware":
                cordova.getThreadPool().execute(() -> {
                    checkMalware(context, callbackContext);
                });
                return true;
            case "checkNetwork":
                cordova.getThreadPool().execute(() -> {
                    checkNetwork(context, callbackContext);
                });
                return true;
            case "checkScreenMirroring":
                cordova.getThreadPool().execute(() -> {
                    checkScreenMirroring(context, callbackContext);
                });
                return true;
            case "checkAppSpoofing":
                cordova.getThreadPool().execute(() -> {
                    checkAppSpoofing(context, callbackContext);
                });
                return true;
            case "checkKeyLogger":
                cordova.getThreadPool().execute(() -> {
                    checkKeyLogger(context, callbackContext);
                });
                return true;
            case "checkAll":
                cordova.getThreadPool().execute(() -> {
                    securityChecker.runSecurityChecks();
                    callbackContext.success();
                });
                return true;
        }
        return false;
    }

    private void checkRoot(Context context, CallbackContext callbackContext) {
        try {
            SecurityChecker.SecurityCheck result = securityChecker.checkRootStatus();
            handleSecurityCheckResult(context, "Root Access Check", result, callbackContext);
        } catch (Exception e) {
            callbackContext.error("Error checking root status: " + e.getMessage());
        }
    }

    private void checkDeveloperOptions(Context context, CallbackContext callbackContext) {
        try {
            SecurityChecker.SecurityCheck result = securityChecker.checkDeveloperOptions();
            handleSecurityCheckResult(context, "Developer Options Check", result, callbackContext);
        } catch (Exception e) {
            callbackContext.error("Error checking developer options: " + e.getMessage());
        }
    }

    private void checkMalware(Context context, CallbackContext callbackContext) {
        try {
            SecurityChecker.SecurityCheck result = securityChecker.checkMalwareAndTampering();
            handleSecurityCheckResult(context, "Malware Check", result, callbackContext);
        } catch (Exception e) {
            callbackContext.error("Error checking malware: " + e.getMessage());
        }
    }

    private void checkNetwork(Context context, CallbackContext callbackContext) {
        try {
            SecurityChecker.SecurityCheck result = securityChecker.checkNetworkSecurity();
            handleSecurityCheckResult(context, "Network Security Check", result, callbackContext);
        } catch (Exception e) {
            callbackContext.error("Error checking network security: " + e.getMessage());
        }
    }

    private void checkScreenMirroring(Context context, CallbackContext callbackContext) {
        try {
            SecurityChecker.SecurityCheck result = securityChecker.checkScreenMirroring();
            handleSecurityCheckResult(context, "Screen Mirroring Check", result, callbackContext);
        } catch (Exception e) {
            callbackContext.error("Error checking screen mirroring: " + e.getMessage());
        }
    }

    private void checkAppSpoofing(Context context, CallbackContext callbackContext) {
        try {
            SecurityChecker.SecurityCheck result = securityChecker.checkAppSpoofing();
            handleSecurityCheckResult(context, "App Spoofing Check", result, callbackContext);
        } catch (Exception e) {
            callbackContext.error("Error checking app spoofing: " + e.getMessage());
        }
    }

    private void checkKeyLogger(Context context, CallbackContext callbackContext) {
        try {
            SecurityChecker.SecurityCheck result = securityChecker.checkKeyLoggerDetection();
            handleSecurityCheckResult(context, "Keylogger Check", result, callbackContext);
        } catch (Exception e) {
            callbackContext.error("Error checking keylogger: " + e.getMessage());
        }
    }

    private void handleSecurityCheckResult(Context context, String checkName, SecurityChecker.SecurityCheck result, CallbackContext callbackContext) {
        if (result instanceof SecurityChecker.SecurityCheck.Success) {
            callbackContext.success(checkName + ": Passed");
        } else {
            showSecurityViolation(context, checkName, result);
        }
    }

    private void showSecurityViolation(Context context, String title, SecurityChecker.SecurityCheck check) {
        cordova.getActivity().runOnUiThread(() -> {
            if (check instanceof SecurityChecker.SecurityCheck.Warning) {
                SecurityChecker.SecurityCheck.Warning warning = (SecurityChecker.SecurityCheck.Warning) check;
                securityChecker.showSecurityDialog(context, warning.getMessage(), false);
            } else if (check instanceof SecurityChecker.SecurityCheck.Critical) {
                SecurityChecker.SecurityCheck.Critical critical = (SecurityChecker.SecurityCheck.Critical) check;
                securityChecker.showSecurityDialog(context, critical.getMessage(), true);
            }
        });
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        if (securityChecker != null) {
            securityChecker.cleanup();
        }
    }
}
