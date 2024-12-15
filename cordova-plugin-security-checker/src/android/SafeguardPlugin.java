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
        String expectedPackageName = preferences.getString("EXPECTED_PACKAGE_NAME", cordova.getActivity().getPackageName());

        // Initialize SecurityConfigManager with the configuration from config.xml
        SecurityConfigManager.INSTANCE.initialize(
            cordova.getActivity().getApplicationContext(),
            new SecurityChecker.SecurityConfig(
                SecurityChecker.SecurityCheckState.fromString(rootCheckState),
                SecurityChecker.SecurityCheckState.fromString(devOptionsCheckState),
                SecurityChecker.SecurityCheckState.fromString(malwareCheckState),
                SecurityChecker.SecurityCheckState.fromString(tamperingCheckState),
                SecurityChecker.SecurityCheckState.fromString(networkSecurityCheckState),
                SecurityChecker.SecurityCheckState.fromString(screenSharingCheckState),
                SecurityChecker.SecurityCheckState.fromString(appSpoofingCheckState),
                SecurityChecker.SecurityCheckState.fromString(keyloggerCheckState),
                expectedPackageName
            )
        );
        
        // Get the SecurityChecker instance
        securityChecker = SecurityConfigManager.INSTANCE.getSecurityChecker();
    }

    @Override
    public void onResume(boolean multitasking) {
        super.onResume(multitasking);
        
        // Perform security checks when the app resumes
        performSecurityChecks();
    }

    private void performSecurityChecks() {
        Context context = cordova.getActivity().getApplicationContext();
        
        // Run all security checks
        cordova.getThreadPool().execute(() -> {
            try {
                runSecurityChecks(context, (allPassed) -> {
                    if (allPassed && securityCheckCallback != null) {
                        securityCheckCallback.success("All security checks passed");
                    }
                });
            } catch (Exception e) {
                Log.e(TAG, "Error during security checks", e);
                if (securityCheckCallback != null) {
                    securityCheckCallback.error("Error during security checks: " + e.getMessage());
                }
            }
        });
    }

    private void runSecurityChecks(Context context, Consumer<Boolean> callback) {
        // Check root status
        SecurityChecker.SecurityCheck rootCheck = securityChecker.checkRootStatus();
        if (!(rootCheck instanceof SecurityChecker.SecurityCheck.Success)) {
            showSecurityViolation(context, "Root Access Detected", rootCheck);
        }

        // Check developer options
        SecurityChecker.SecurityCheck devCheck = securityChecker.checkDeveloperOptions();
        if (!(devCheck instanceof SecurityChecker.SecurityCheck.Success)) {
            showSecurityViolation(context, "Developer Options Enabled", devCheck);
        }

        // Check malware
        SecurityChecker.SecurityCheck malwareCheck = securityChecker.checkMalwareAndTampering();
        if (!(malwareCheck instanceof SecurityChecker.SecurityCheck.Success)) {
            showSecurityViolation(context, "Malware Detected", malwareCheck);
        }

        // Check network security
        SecurityChecker.SecurityCheck networkCheck = securityChecker.checkNetworkSecurity();
        if (!(networkCheck instanceof SecurityChecker.SecurityCheck.Success)) {
            showSecurityViolation(context, "Network Security Issue", networkCheck);
        }

        // Check screen mirroring
        SecurityChecker.SecurityCheck screenCheck = securityChecker.checkScreenMirroring();
        if (!(screenCheck instanceof SecurityChecker.SecurityCheck.Success)) {
            showSecurityViolation(context, "Screen Mirroring Detected", screenCheck);
        }

        // Check app spoofing
        SecurityChecker.SecurityCheck spoofingCheck = securityChecker.checkAppSpoofing();
        if (!(spoofingCheck instanceof SecurityChecker.SecurityCheck.Success)) {
            showSecurityViolation(context, "App Spoofing Detected", spoofingCheck);
        }

        // Check keylogger
        SecurityChecker.SecurityCheck keyloggerCheck = securityChecker.checkKeyLoggerDetection();
        if (!(keyloggerCheck instanceof SecurityChecker.SecurityCheck.Success)) {
            showSecurityViolation(context, "Keylogger Detected", keyloggerCheck);
        }

        // All checks passed
        callback.accept(true);
    }

    private void showSecurityViolation(Context context, String title, SecurityChecker.SecurityCheck check) {
        String message;
        boolean isCritical;
        
        if (check instanceof SecurityChecker.SecurityCheck.Warning) {
            message = ((SecurityChecker.SecurityCheck.Warning) check).getMessage();
            isCritical = false;
        } else if (check instanceof SecurityChecker.SecurityCheck.Critical) {
            message = ((SecurityChecker.SecurityCheck.Critical) check).getMessage();
            isCritical = true;
        } else {
            return;
        }

        // Show dialog on UI thread
        cordova.getActivity().runOnUiThread(() -> {
            securityChecker.showSecurityDialog(
                cordova.getActivity(),
                message,
                isCritical,
                (continueAnyway) -> {
                    try {
                        JSONObject result = new JSONObject();
                        result.put("title", title);
                        result.put("message", message);
                        result.put("type", isCritical ? "error" : "warning");

                        if (securityCheckCallback != null) {
                            securityCheckCallback.error(result);
                        }

                        // For critical violations, finish the activity
                        if (isCritical) {
                            cordova.getActivity().finish();
                        }
                    } catch (JSONException e) {
                        Log.e(TAG, "Error creating security violation JSON", e);
                    }
                }
            );
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
        this.securityCheckCallback = callbackContext;
        
        if (action.equals("startSecurityChecks")) {
            performSecurityChecks(); // Trigger security checks immediately
            return true;
        }

        Context context = cordova.getActivity().getApplicationContext();

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
                    runSecurityChecks(context, (allPassed) -> {
                        if (allPassed && securityCheckCallback != null) {
                            securityCheckCallback.success("All security checks passed");
                        }
                    });
                });
                return true;
        }
        return false;
    }

    // Individual check methods implementation
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
}
