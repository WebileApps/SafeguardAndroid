package com.webileapps.safeguard.cordova;

import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaWebView;

import org.json.JSONArray;
import org.json.JSONException;

import android.content.Context;
import android.util.Log;

import com.webileapps.safeguard.SecurityChecker;
import com.webileapps.safeguard.SecurityConfigManager;

public class SecurityCheckerPlugin extends CordovaPlugin {
    private static final String TAG = "SecurityCheckerPlugin";

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

        // Initialize SecurityConfigManager with the configuration from config.xml
        SecurityConfigManager.INSTANCE.initialize(
            cordova.getActivity().getApplicationContext(),
            new SecurityChecker.SecurityConfig(
                SecurityChecker.SecurityCheckState.valueOf(rootCheckState),
                SecurityChecker.SecurityCheckState.valueOf(devOptionsCheckState),
                SecurityChecker.SecurityCheckState.valueOf(malwareCheckState),
                SecurityChecker.SecurityCheckState.valueOf(tamperingCheckState),
                SecurityChecker.SecurityCheckState.valueOf(networkSecurityCheckState),
                SecurityChecker.SecurityCheckState.valueOf(screenSharingCheckState),
                SecurityChecker.SecurityCheckState.valueOf(appSpoofingCheckState),
                SecurityChecker.SecurityCheckState.valueOf(keyloggerCheckState)
            )
        );
    }

    private String getSecurityCheckState(String preferenceName, String defaultValue) {
        String value = preferences.getString(preferenceName, defaultValue);
        // Validate that the value is a valid SecurityCheckState
        try {
            SecurityChecker.SecurityCheckState.valueOf(value);
            return value;
        } catch (IllegalArgumentException e) {
            Log.w(TAG, "Invalid security check state for " + preferenceName + ": " + value + ". Using default: " + defaultValue);
            return defaultValue;
        }
    }

    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
        Context context = cordova.getActivity().getApplicationContext();
        SecurityChecker securityChecker = SecurityConfigManager.INSTANCE.getSecurityChecker();

        switch (action) {
            case "checkRoot":
                cordova.getThreadPool().execute(() -> {
                    checkRoot(context, securityChecker, callbackContext);
                });
                return true;
            case "checkDeveloperOptions":
                cordova.getThreadPool().execute(() -> {
                    checkDeveloperOptions(context, securityChecker, callbackContext);
                });
                return true;
            case "checkMalware":
                cordova.getThreadPool().execute(() -> {
                    checkMalware(context, securityChecker, callbackContext);
                });
                return true;
            case "checkNetwork":
                cordova.getThreadPool().execute(() -> {
                    checkNetwork(context, securityChecker, callbackContext);
                });
                return true;
            case "checkScreenMirroring":
                cordova.getThreadPool().execute(() -> {
                    checkScreenMirroring(context, securityChecker, callbackContext);
                });
                return true;
            case "checkAppSpoofing":
                cordova.getThreadPool().execute(() -> {
                    checkAppSpoofing(context, securityChecker, callbackContext);
                });
                return true;
            case "checkKeyLogger":
                cordova.getThreadPool().execute(() -> {
                    checkKeyLogger(context, securityChecker, callbackContext);
                });
                return true;
        }
        return false;
    }

    // Individual check methods implementation...
    private void checkRoot(Context context, SecurityChecker checker, CallbackContext callbackContext) {
        try {
            SecurityChecker.SecurityCheck result = checker.checkRootStatus();
            handleSecurityCheckResult(result, callbackContext);
        } catch (Exception e) {
            callbackContext.error("Error checking root status: " + e.getMessage());
        }
    }

    private void checkDeveloperOptions(Context context, SecurityChecker checker, CallbackContext callbackContext) {
        try {
            SecurityChecker.SecurityCheck result = checker.checkDeveloperOptions();
            handleSecurityCheckResult(result, callbackContext);
        } catch (Exception e) {
            callbackContext.error("Error checking developer options: " + e.getMessage());
        }
    }

    private void checkMalware(Context context, SecurityChecker checker, CallbackContext callbackContext) {
        try {
            SecurityChecker.SecurityCheck result = checker.checkMalwareAndTampering();
            handleSecurityCheckResult(result, callbackContext);
        } catch (Exception e) {
            callbackContext.error("Error checking malware: " + e.getMessage());
        }
    }

    private void checkNetwork(Context context, SecurityChecker checker, CallbackContext callbackContext) {
        try {
            SecurityChecker.SecurityCheck result = checker.checkNetworkSecurity();
            handleSecurityCheckResult(result, callbackContext);
        } catch (Exception e) {
            callbackContext.error("Error checking network security: " + e.getMessage());
        }
    }

    private void checkScreenMirroring(Context context, SecurityChecker checker, CallbackContext callbackContext) {
        try {
            SecurityChecker.SecurityCheck result = checker.checkScreenMirroring();
            handleSecurityCheckResult(result, callbackContext);
        } catch (Exception e) {
            callbackContext.error("Error checking screen mirroring: " + e.getMessage());
        }
    }

    private void checkAppSpoofing(Context context, SecurityChecker checker, CallbackContext callbackContext) {
        try {
            SecurityChecker.SecurityCheck result = checker.checkAppSpoofing();
            handleSecurityCheckResult(result, callbackContext);
        } catch (Exception e) {
            callbackContext.error("Error checking app spoofing: " + e.getMessage());
        }
    }

    private void checkKeyLogger(Context context, SecurityChecker checker, CallbackContext callbackContext) {
        try {
            SecurityChecker.SecurityCheck result = checker.checkKeyLoggerDetection();
            handleSecurityCheckResult(result, callbackContext);
        } catch (Exception e) {
            callbackContext.error("Error checking keylogger: " + e.getMessage());
        }
    }

    private void handleSecurityCheckResult(SecurityChecker.SecurityCheck result, CallbackContext callbackContext) {
        if (result instanceof SecurityChecker.SecurityCheck.Success) {
            callbackContext.success("Security check passed");
        } else if (result instanceof SecurityChecker.SecurityCheck.Warning) {
            SecurityChecker.SecurityCheck.Warning warning = (SecurityChecker.SecurityCheck.Warning) result;
            callbackContext.success(warning.getMessage());
        } else if (result instanceof SecurityChecker.SecurityCheck.Critical) {
            SecurityChecker.SecurityCheck.Critical critical = (SecurityChecker.SecurityCheck.Critical) result;
            callbackContext.error(critical.getMessage());
        }
    }
}
