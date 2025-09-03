package com.webileapps.safeguard;

import android.content.Context;

public class SecurityConfigManager {
    private static SecurityChecker.SecurityConfig config;
    private static SecurityChecker securityChecker;
    private static FridaDetection fridaDetection;

    public static void initialize(Context context, SecurityChecker.SecurityConfig configuration) {
        config = configuration;
        securityChecker = new SecurityChecker(context, configuration);
        if (configuration.getRootCheck() != SecurityChecker.SecurityCheckState.DISABLED) {
            securityChecker.startFridaDetection();
            fridaDetection = new FridaDetection(context);
            // Initialize protection immediately
            fridaDetection.initializeProtection();

            // Start continuous monitoring (check every 5 seconds)
            fridaDetection.startContinuousMonitoring(100000);

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
