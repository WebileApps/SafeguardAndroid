package com.webileapps.safeguard

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import android.widget.Toast
import com.webileapps.safeguard.SecurityChecker.SecurityCheck

fun Context.showToast(message: String) {
    Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
}

fun Context.checkRoot(securityChecker: SecurityChecker,onChecked: (Boolean) -> Unit) {

    val result = securityChecker.checkRootStatus()
    return when (result) {
        is SecurityChecker.SecurityCheck.Critical -> {
            SecurityChecker.showSecurityDialog(AppActivity.context, result.message, isCritical = true)
            onChecked(false)
        }
        is SecurityChecker.SecurityCheck.Warning -> {

            SecurityChecker.showSecurityDialog(AppActivity.context, result.message, isCritical = false) { userAcknowledged ->
                if (userAcknowledged) {
                    onChecked(true)
                }
            }

        }
        is SecurityChecker.SecurityCheck.Success -> {
            onChecked(true)
        }
    }
}

fun Context.checkDeveloperOptions(securityChecker: SecurityChecker,onChecked: (Boolean) -> Unit) {
    when (val result = securityChecker.checkDeveloperOptions()) {
        is SecurityChecker.SecurityCheck.Critical -> {
            SecurityChecker.showSecurityDialog(AppActivity.context, result.message, true)
            onChecked(false)

        }
        is SecurityChecker.SecurityCheck.Warning -> {
            SecurityChecker.showSecurityDialog(AppActivity.context, result.message, false){userAcknowledged ->
                if (userAcknowledged) {
                    onChecked(true)
                }
            }
        }
        is SecurityChecker.SecurityCheck.Success -> {
            onChecked(true)
        }
    }
}

fun Context.checkMalware(securityChecker: SecurityChecker,onChecked: (Boolean) -> Unit) {
    when (val result = securityChecker.checkMalwareAndTampering()) {
        is SecurityChecker.SecurityCheck.Critical -> {
            SecurityChecker.showSecurityDialog(AppActivity.context, result.message, true)
        }
        is SecurityChecker.SecurityCheck.Warning -> {
            SecurityChecker.showSecurityDialog(AppActivity.context, result.message, false){userAcknowledged ->
                if (userAcknowledged) {
                    onChecked(true)
                }
            }
        }
        is SecurityChecker.SecurityCheck.Success -> {
            onChecked(true)
        }
    }
}
fun Context.checkScreenMirroring(securityChecker: SecurityChecker,onChecked: (Boolean) -> Unit) {
    when (val result = securityChecker.checkScreenMirroring()) {
        is SecurityChecker.SecurityCheck.Warning -> {
            SecurityChecker.showSecurityDialog(AppActivity.context, result.message, false){userAcknowledged ->
                if (userAcknowledged) {
                    onChecked(true)
                }
            }
        }
        is SecurityChecker.SecurityCheck.Success -> {
            onChecked(true)
        }
        else -> { onChecked(true)}
    }
}

fun Context.checkApplicationSpoofing(securityChecker: SecurityChecker,onChecked: (Boolean) -> Unit) {
    when (val result = securityChecker.checkAppSpoofing()) {
        is SecurityChecker.SecurityCheck.Warning -> {
            SecurityChecker.showSecurityDialog(AppActivity.context, result.message, false){userAcknowledged ->
                if (userAcknowledged) {
                    onChecked(true)
                }
            }
        }
        is SecurityChecker.SecurityCheck.Success -> {
            onChecked(true)
        }
        else -> { onChecked(true)}
    }
}

fun Context.checkKeyLoggerDetection(securityChecker: SecurityChecker,onChecked: (Boolean) -> Unit) {
    when (val result = securityChecker.checkKeyLoggerDetection()) {
        is SecurityChecker.SecurityCheck.Warning -> {
            SecurityChecker.showSecurityDialog(AppActivity.context, result.message, false) { userAcknowledged ->
                if (userAcknowledged) {
                    onChecked(true)
                }
            }
        }

        is SecurityChecker.SecurityCheck.Success -> {
            onChecked(true)
        }

        else -> {
            onChecked(true)
        }
    }
}

fun Context.checkNetwork(securityChecker: SecurityChecker,onChecked: (Boolean) -> Unit) {
    when (val result = securityChecker.checkNetworkSecurity()) {
        is SecurityChecker.SecurityCheck.Warning -> {
            SecurityChecker.showSecurityDialog(AppActivity.context, result.message, false) { userAcknowledged ->
                if (userAcknowledged) {
                    onChecked(true)
                }
            }
        }
        is SecurityChecker.SecurityCheck.Success -> {
           onChecked(true)
        }
        else -> {onChecked(true)}
    }
}

fun Context.showSecurityDialogForCheck(checkResult: SecurityCheck, isCritical: Boolean, onResponse: ((Boolean) -> Unit)? = null) {
    when (checkResult) {
        is SecurityCheck.Critical -> {
            SecurityChecker.showSecurityDialog(AppActivity.context, checkResult.message, isCritical = true, onResponse)
        }
        is SecurityCheck.Warning -> {
            SecurityChecker.showSecurityDialog(AppActivity.context, checkResult.message, isCritical = false, onResponse)
        }
        is SecurityCheck.Success -> {
            onResponse?.invoke(true)
        }
    }
}

fun getPackageName(context: Context):String{
    val applicationInfo = context.packageManager.getApplicationInfo(context.packageName,
        PackageManager.GET_META_DATA)
    return applicationInfo.metaData.getString("package_name","")
}