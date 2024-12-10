package com.kfintech.protect.cordova;

import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaWebView;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.kfintech.protect.SecurityChecker;
import android.app.Activity;

public class SecurityCheckerPlugin extends CordovaPlugin {
    private SecurityChecker securityChecker;

    @Override
    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        super.initialize(cordova, webView);
        
        // Get preferences from config.xml
        boolean treatRootAsWarning = 
            preferences.getBoolean("TREAT_ROOT_AS_WARNING", false);
        boolean treatDeveloperOptionsAsWarning = 
            preferences.getBoolean("TREAT_DEVELOPER_OPTIONS_AS_WARNING", false);
        boolean treatMalwareAsWarning = 
            preferences.getBoolean("TREAT_MALWARE_AS_WARNING", false);
        boolean treatTamperingAsWarning = 
            preferences.getBoolean("TREAT_TAMPERING_AS_WARNING", false);

        // Initialize SecurityChecker with preferences
        SecurityChecker.SecurityConfig config = new SecurityChecker.SecurityConfig(
            treatRootAsWarning,
            treatDeveloperOptionsAsWarning,
            treatMalwareAsWarning,
            treatTamperingAsWarning
        );
        
        securityChecker = new SecurityChecker(cordova.getActivity(), config);
    }

    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
        Activity activity = cordova.getActivity();
        
        switch (action) {
            case "checkSecurity":
                checkSecurity(activity, callbackContext);
                return true;
            case "checkRoot":
                checkRoot(activity, callbackContext);
                return true;
            case "checkDeveloperOptions":
                checkDeveloperOptions(activity, callbackContext);
                return true;
            case "checkNetwork":
                checkNetwork(activity, callbackContext);
                return true;
            case "checkMalware":
                checkMalware(activity, callbackContext);
                return true;
            case "checkScreenMirroring":
                checkScreenMirroring(activity, callbackContext);
                return true;
            default:
                return false;
        }
    }

    private void checkSecurity(Activity activity, final CallbackContext callbackContext) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                JSONObject result = new JSONObject();
                try {
                    result.put("root", checkSecurityItem(securityChecker.checkRootStatus()));
                    result.put("developerOptions", checkSecurityItem(securityChecker.checkDeveloperOptions()));
                    result.put("network", checkSecurityItem(securityChecker.checkNetworkSecurity()));
                    result.put("malware", checkSecurityItem(securityChecker.checkMalwareAndTampering()));
                    result.put("screenMirroring", checkSecurityItem(securityChecker.checkScreenMirroring()));
                    callbackContext.success(result);
                } catch (JSONException e) {
                    callbackContext.error("Error creating JSON response");
                }
            }
        });
    }

    private void checkRoot(Activity activity, final CallbackContext callbackContext) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                SecurityChecker.SecurityCheck result = securityChecker.checkRootStatus();
                handleSecurityResult(result, callbackContext);
            }
        });
    }

    private void checkDeveloperOptions(Activity activity, final CallbackContext callbackContext) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                SecurityChecker.SecurityCheck result = securityChecker.checkDeveloperOptions();
                handleSecurityResult(result, callbackContext);
            }
        });
    }

    private void checkNetwork(Activity activity, final CallbackContext callbackContext) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                SecurityChecker.SecurityCheck result = securityChecker.checkNetworkSecurity();
                handleSecurityResult(result, callbackContext);
            }
        });
    }

    private void checkMalware(Activity activity, final CallbackContext callbackContext) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                SecurityChecker.SecurityCheck result = securityChecker.checkMalwareAndTampering();
                handleSecurityResult(result, callbackContext);
            }
        });
    }

    private void checkScreenMirroring(Activity activity, final CallbackContext callbackContext) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                SecurityChecker.SecurityCheck result = securityChecker.checkScreenMirroring();
                handleSecurityResult(result, callbackContext);
            }
        });
    }

    private JSONObject checkSecurityItem(SecurityChecker.SecurityCheck check) throws JSONException {
        JSONObject item = new JSONObject();
        if (check instanceof SecurityChecker.SecurityCheck.Success) {
            item.put("status", "success");
            item.put("message", "");
        } else if (check instanceof SecurityChecker.SecurityCheck.Warning) {
            item.put("status", "warning");
            item.put("message", ((SecurityChecker.SecurityCheck.Warning) check).getMessage());
        } else if (check instanceof SecurityChecker.SecurityCheck.Critical) {
            item.put("status", "critical");
            item.put("message", ((SecurityChecker.SecurityCheck.Critical) check).getMessage());
        }
        return item;
    }

    private void handleSecurityResult(SecurityChecker.SecurityCheck result, CallbackContext callbackContext) {
        try {
            callbackContext.success(checkSecurityItem(result));
        } catch (JSONException e) {
            callbackContext.error("Error creating JSON response");
        }
    }
}
