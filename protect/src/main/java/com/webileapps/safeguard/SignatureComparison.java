package com.webileapps.safeguard;

import android.content.Context;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.os.Build;
import android.util.Log;
import java.security.MessageDigest;

public class SignatureComparison {
    private static final String TAG = "AppSignatureVerifier";

    public boolean isAppSignatureValid(Context context, String expectedSignatureHash) {
        try {
            PackageManager packageManager = context.getPackageManager();
            String packageName = context.getPackageName();
            android.content.pm.PackageInfo packageInfo;
            
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                packageInfo = packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES);
            } else {
                packageInfo = packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNATURES);
            }

            Signature[] signatures;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                SigningInfo signingInfo = packageInfo.signingInfo;
                if (signingInfo != null) {
                    signatures = signingInfo.getApkContentsSigners();
                } else {
                    signatures = null;
                }
            } else {
                signatures = packageInfo.signatures;
            }

            if (signatures == null || signatures.length == 0) {
                Log.e(TAG, "No signatures found for the app.");
                return false;
            }

            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] originalDigest = md.digest(expectedSignatureHash.getBytes());
            byte[] currentDigest = md.digest(signatures[0].toByteArray());

            boolean isValid = MessageDigest.isEqual(originalDigest, currentDigest);
            if (isValid) {
                Log.d(TAG, "App signature is valid.");
            } else {
                Log.e(TAG, "App signature is invalid! Possible tampering detected.");
            }

            return isValid;
        } catch (Exception e) {
            Log.e(TAG, "Error verifying app signature", e);
            return false;
        }
    }
}
