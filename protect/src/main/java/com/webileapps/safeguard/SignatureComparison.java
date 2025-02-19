package com.webileapps.safeguard;

import android.content.Context;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.os.Build;
import android.util.Log;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SignatureComparison {
    private static final String TAG = "AppSignatureVerifier";
    private static final String HASH_ALGORITHM = String.join("-", "SHA", "256");
    
    public boolean isAppSignatureValid(Context context, String expectedSignatureHash) {
        try {
            // Validate input parameters
            if (context == null || expectedSignatureHash == null) {
                throw new IllegalArgumentException("Null context or expected hash");
            }

            final String packageName = context.getPackageName();
            final Signature signature = getAppSignature(context, packageName);
            
            if (signature == null) {
                Log.e(TAG, "No valid signature found");
                return false;
            }

            final String currentHash = calculateSignatureHash(signature);
            final String normalizedExpected = normalizeHash(expectedSignatureHash);
            final String normalizedCurrent = normalizeHash(currentHash);

            final boolean isValid = constantTimeEquals(normalizedExpected, normalizedCurrent);
            
            if (!isValid) {
                Log.w(TAG, "Signature mismatch!\n" +
                        "Expected: " + normalizedExpected + "\n" +
                        "Actual:   " + normalizedCurrent);
            }
            
            return isValid;
        } catch (Exception e) {
            Log.e(TAG, "Signature verification failed: " + e.getMessage());
            return false;
        }
    }

    private Signature getAppSignature(Context context, String packageName) 
        throws PackageManager.NameNotFoundException {
        final PackageManager pm = context.getPackageManager();
        final int flags = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P ?
            PackageManager.GET_SIGNING_CERTIFICATES :
            PackageManager.GET_SIGNATURES;

        final android.content.pm.PackageInfo packageInfo = pm.getPackageInfo(packageName, flags);
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            final SigningInfo signingInfo = packageInfo.signingInfo;
            return (signingInfo != null && signingInfo.hasMultipleSigners()) ? 
                signingInfo.getApkContentsSigners()[0] : 
                signingInfo != null ? signingInfo.getSigningCertificateHistory()[0] : null;
        }
        return packageInfo.signatures != null ? packageInfo.signatures[0] : null;
    }

    private String calculateSignatureHash(Signature signature) 
        throws NoSuchAlgorithmException {
        final MessageDigest md = MessageDigest.getInstance(HASH_ALGORITHM);
        final byte[] hashBytes = md.digest(signature.toByteArray());
        return bytesToHex(hashBytes);
    }

    // Constant-time comparison to prevent timing attacks
    private boolean constantTimeEquals(String a, String b) {
        if (a.length() != b.length()) {
            return false;
        }

        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }

    private String normalizeHash(String hash) {
        return hash.replaceAll("[^A-Fa-f0-9]", "").toUpperCase();
    }

    private static String bytesToHex(byte[] bytes) {
        final char[] hexChars = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            final int v = bytes[i] & 0xFF;
            hexChars[i * 2] = "0123456789ABCDEF".charAt(v >>> 4);
            hexChars[i * 2 + 1] = "0123456789ABCDEF".charAt(v & 0x0F);
        }
        return new String(hexChars);
    }
}