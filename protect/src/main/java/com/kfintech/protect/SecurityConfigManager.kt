package com.kfintech.protect

import android.content.Context

object SecurityConfigManager {
    private var config: SecurityChecker.SecurityConfig? = null
    private var securityChecker: SecurityChecker? = null

    fun initialize(context: Context, config: SecurityChecker.SecurityConfig) {
        this.config = config
        this.securityChecker = SecurityChecker(context, config)
    }

    fun getSecurityChecker(): SecurityChecker {
        return securityChecker ?: throw IllegalStateException(
            "SecurityConfigManager not initialized. Call initialize() first with a Context and SecurityConfig."
        )
    }

    fun getConfig(): SecurityChecker.SecurityConfig {
        return config ?: SecurityChecker.SecurityConfig(
            rootCheck = SecurityChecker.SecurityCheckState.ERROR,
            developerOptionsCheck = SecurityChecker.SecurityCheckState.ERROR,
            malwareCheck = SecurityChecker.SecurityCheckState.ERROR,
            tamperingCheck = SecurityChecker.SecurityCheckState.ERROR,
            networkSecurityCheck = SecurityChecker.SecurityCheckState.WARNING,
            screenSharingCheck = SecurityChecker.SecurityCheckState.WARNING,
            appSpoofingCheck = SecurityChecker.SecurityCheckState.WARNING,
            keyloggerCheck = SecurityChecker.SecurityCheckState.WARNING
        )
    }
}
