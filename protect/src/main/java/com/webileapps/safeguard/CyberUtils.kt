package com.webileapps.safeguard

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.provider.Settings
import android.widget.Toast

fun Context.showToast(message: String) {
    Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
}

fun Context.checkRoot(securityChecker: SecurityChecker, onChecked: (Boolean) -> Unit) {
    val result = securityChecker.checkRootStatus()
    when (result) {
        is SecurityChecker.SecurityCheck.Critical -> {
            SecurityConfigManager.getSecurityChecker().showSecurityDialog(AppActivity.context, result.message, isCritical = true)
            onChecked(false)
        }
        is SecurityChecker.SecurityCheck.Warning -> {
            SecurityConfigManager.getSecurityChecker().showSecurityDialog(AppActivity.context, result.message, isCritical = false) { userAcknowledged ->
                if (userAcknowledged) {
                    onChecked(true)
                }
            }
        }
        else -> {
            onChecked(true)
        }
    }
}

fun Context.checkDeveloperOptions(securityChecker: SecurityChecker, onChecked: (Boolean) -> Unit) {
    when (val result = securityChecker.checkDeveloperOptions()) {
        is SecurityChecker.SecurityCheck.Critical -> {
            SecurityConfigManager.getSecurityChecker().showSecurityDialog(AppActivity.context, result.message, true)
            onChecked(false)
        }
        is SecurityChecker.SecurityCheck.Warning -> {
            SecurityConfigManager.getSecurityChecker().showSecurityDialog(AppActivity.context, result.message, false) { userAcknowledged ->
                if (userAcknowledged) {
                    onChecked(true)
                }
            }
        }
        else -> onChecked(true)
    }
}

fun Context.checkMalware(securityChecker: SecurityChecker, onChecked: (Boolean) -> Unit) {
    when (val result = securityChecker.checkMalwareAndTampering()) {
        is SecurityChecker.SecurityCheck.Critical -> {
            SecurityConfigManager.getSecurityChecker().showSecurityDialog(AppActivity.context, result.message, true)
        }
        is SecurityChecker.SecurityCheck.Warning -> {
            SecurityConfigManager.getSecurityChecker().showSecurityDialog(AppActivity.context, result.message, false) { userAcknowledged ->
                if (userAcknowledged) {
                    onChecked(true)
                }
            }
        }
        else -> onChecked(true)
    }
}

fun Context.checkScreenMirroring(securityChecker: SecurityChecker, onChecked: (Boolean) -> Unit) {
    when (val result = securityChecker.checkScreenMirroring()) {
        is SecurityChecker.SecurityCheck.Warning -> {
            SecurityConfigManager.getSecurityChecker().showSecurityDialog(AppActivity.context, result.message, false) { userAcknowledged ->
                if (userAcknowledged) {
                    onChecked(true)
                }
            }
        }
        else -> onChecked(true)
    }
}

fun Context.checkApplicationSpoofing(securityChecker: SecurityChecker, onChecked: (Boolean) -> Unit) {
    when (val result = securityChecker.checkAppSpoofing()) {
        is SecurityChecker.SecurityCheck.Warning -> {
            SecurityConfigManager.getSecurityChecker().showSecurityDialog(AppActivity.context, result.message, false) { userAcknowledged ->
                if (userAcknowledged) {
                    onChecked(true)
                }
            }
        }
        else -> onChecked(true)
    }
}

fun Context.checkKeyLoggerDetection(securityChecker: SecurityChecker, onChecked: (Boolean) -> Unit) {
    when (val result = securityChecker.checkKeyLoggerDetection()) {
        is SecurityChecker.SecurityCheck.Warning -> {
            SecurityConfigManager.getSecurityChecker().showSecurityDialog(AppActivity.context, result.message, false) { userAcknowledged ->
                if (userAcknowledged) {
                    onChecked(true)
                }
            }
        }
        else -> onChecked(true)
    }
}

fun Context.checkNetwork(securityChecker: SecurityChecker, onChecked: (Boolean) -> Unit) {
    when (val result = securityChecker.checkNetworkSecurity()) {
        is SecurityChecker.SecurityCheck.Warning -> {
            SecurityConfigManager.getSecurityChecker().showSecurityDialog(AppActivity.context, result.message, false) { userAcknowledged ->
                if (userAcknowledged) {
                    onChecked(true)
                }
            }
        }
        else -> onChecked(true)
    }
}

fun Context.showSecurityDialogForCheck(checkResult: SecurityChecker.SecurityCheck, isCritical: Boolean, onResponse: ((Boolean) -> Unit)? = null) {
    when (checkResult) {
        is SecurityChecker.SecurityCheck.Critical -> {
            SecurityConfigManager.getSecurityChecker().showSecurityDialog(AppActivity.context, checkResult.message, isCritical = true, onResponse)
        }
        is SecurityChecker.SecurityCheck.Warning -> {
            SecurityConfigManager.getSecurityChecker().showSecurityDialog(AppActivity.context, checkResult.message, isCritical = false, onResponse)
        }
        else -> {}
    }
}