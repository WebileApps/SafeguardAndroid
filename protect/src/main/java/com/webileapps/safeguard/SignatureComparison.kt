package com.webileapps.safeguard

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import java.security.MessageDigest


class SignatureComparison {

    val TAG: String = "AppSignatureVerifier"

    fun isAppSignatureValid(context: Context, expectedSignatureHash: String): Boolean {
        return try {
            val packageManager = context.packageManager
            val packageName = context.packageName
            val packageInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
            } else {
                @Suppress("DEPRECATION")
                packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNATURES)
            }

            val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                packageInfo.signingInfo?.apkContentsSigners
            } else {
                @Suppress("DEPRECATION")
                packageInfo.signatures
            }

            if (signatures == null || signatures.isEmpty()) {
                Log.e(TAG, "No signatures found for the app.")
                return false
            }


            val md = MessageDigest.getInstance("SHA-1");
            val originalDigest = md.digest(expectedSignatureHash.toByteArray())

            val currentDigest = md.digest(signatures[0].toByteArray())


            // Compare with the expected signature hash
            val isValid = MessageDigest.isEqual(originalDigest, currentDigest)
            if (isValid) {
                Log.d(TAG, "App signature is valid.")
            } else {
                Log.e(TAG, "App signature is invalid! Possible tampering detected.")
            }

            isValid
        } catch (e: Exception) {
            Log.e(TAG, "Error verifying app signature", e)
            false
        }
    }

    }