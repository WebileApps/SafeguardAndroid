package com.webileapps.safeguard;

import android.content.Context;

public class SecurityConfigManager {
    private static SecurityChecker.SecurityConfig config;
    private static SecurityChecker securityChecker;

    public static void initialize(Context context, SecurityChecker.SecurityConfig configuration) {
        config = configuration;
        securityChecker = new SecurityChecker(context, configuration);
        if (configuration.getRootCheck() != SecurityChecker.SecurityCheckState.DISABLED) {
            securityChecker.startFridaDetection();
        }
    }

    public static SecurityChecker getSecurityChecker() {
        if (securityChecker == null) {
            throw new IllegalStateException(
                "SecurityConfigManager not initialized. Call initialize() first with a Context and SecurityConfig."
            );
        }
        return securityChecker;
    }

    public static SecurityChecker.SecurityConfig getConfig() {
        if (config == null) {
            return new SecurityChecker.SecurityConfig(
                SecurityChecker.SecurityCheckState.ERROR,    // rootCheck
                SecurityChecker.SecurityCheckState.ERROR,    // developerOptionsCheck
                SecurityChecker.SecurityCheckState.ERROR,    // malwareCheck
                SecurityChecker.SecurityCheckState.ERROR,    // tamperingCheck
                SecurityChecker.SecurityCheckState.WARNING,  // appSpoofingCheck
                SecurityChecker.SecurityCheckState.WARNING,  // networkSecurityCheck
                SecurityChecker.SecurityCheckState.WARNING,  // screenSharingCheck
                SecurityChecker.SecurityCheckState.WARNING,   // keyloggerCheck
                SecurityChecker.SecurityCheckState.WARNING,   // onGoingCallCheck
                SecurityChecker.SecurityCheckState.WARNING,   // appSignatureCheck
                "",
                    ""
            );
        }
        return config;
    }
}
