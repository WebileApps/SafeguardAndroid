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

            // Compute SHA-1 hash of the first signature
            val appSignatureHash = getSHA1Hash(signatures[0].toByteArray())
            if (appSignatureHash.isNullOrEmpty()) {
                Log.e(TAG, "Error generating hash for the app's signature.")
                return false
            }

            // Compare with the expected signature hash
            val isValid = expectedSignatureHash.equals(appSignatureHash, ignoreCase = true)
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


    private fun getSHA1Hash(signatureBytes: ByteArray): String? {
        try {
            val digest = MessageDigest.getInstance("SHA-1")
            val hash = digest.digest(signatureBytes)

            // Convert hash to a hexadecimal string
            val hexString = StringBuilder()
            for (b in hash) {
                hexString.append(String.format("%02x", b))
            }
            return hexString.toString()
        } catch (e: Exception) {
            Log.e(TAG, "Error generating SHA-1 hash", e)
            return null
        }
    }
    }