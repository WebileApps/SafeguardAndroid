package com.webileapps.safeguard;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.util.Log;
import androidx.lifecycle.DefaultLifecycleObserver;
import androidx.lifecycle.LifecycleOwner;
import androidx.annotation.NonNull;

public class AppLifecycleObserver implements DefaultLifecycleObserver {
    private final Context context;
    private SecurityChecker securityChecker;

    public AppLifecycleObserver(Context context) {
        this.context = context;
    }

    @Override
    public void onStart(@NonNull LifecycleOwner owner) {
        Log.e("APP>>>", "App is in Foreground");
        // Perform security checks in sequence
        performSecurityChecks();
    }

    private void performSecurityChecks() {
        securityChecker = SecurityConfigManager.getSecurityChecker();
        securityChecker.runSecurityChecks();
    }

    @Override
    public void onStop(@NonNull LifecycleOwner owner) {
        Log.e("APP>>>", "App is in Background");
        if (securityChecker != null) {
            securityChecker.cleanup();
        }
    }

    private void detectOverlayApps(Context context) {
        PackageManager pm = context.getPackageManager();
        for (PackageInfo packageInfo : pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)) {
            String[] requestedPermissions = packageInfo.requestedPermissions;
            if (requestedPermissions != null) {
                for (String permission : requestedPermissions) {
                    if ("android.permission.SYSTEM_ALERT_WINDOW".equals(permission)) {
                        // Log or handle apps with SYSTEM_ALERT_WINDOW permission
                        Log.d("OverlayDetection", "App using SYSTEM_ALERT_WINDOW: " + packageInfo.packageName);
                    }
                }
            }
        }
    }
}
