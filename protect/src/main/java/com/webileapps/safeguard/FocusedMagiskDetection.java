package com.webileapps.safeguard;

import android.content.Context;
import android.content.pm.PackageManager;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.InputStreamReader;

public class FocusedMagiskDetection {
    private static final String TAG = "MagiskDetection";
    private final Context context;

    public FocusedMagiskDetection(Context context) {
        this.context = context;
    }

    /**
     * Main Magisk detection - requires MULTIPLE indicators
     */
    public boolean isMagiskPresent() {
        int detectionCount = 0;

        if (checkMagiskApp()) detectionCount++;
        if (checkMagiskFiles()) detectionCount++;
        if (checkMagiskDaemon()) detectionCount++;
        if (checkMagiskMount()) detectionCount++;
        if (checkZygisk()) detectionCount++;

        // Require at least 2 indicators to reduce false positives
        Log.d(TAG, "Magisk indicators found: " + detectionCount);
        return detectionCount >= 2;
    }

    /**
     * Check for Magisk app (most reliable)
     */
    private boolean checkMagiskApp() {
        String[] magiskPackages = {
                "com.topjohnwu.magisk",
                "io.github.huskydg.magisk",
                "io.github.vvb2060.magisk",
                "com.topjohnwu.magisk.canary"
        };

        PackageManager pm = context.getPackageManager();
        for (String pkg : magiskPackages) {
            try {
                pm.getPackageInfo(pkg, 0);
                Log.d(TAG, "Found Magisk app: " + pkg);
                return true;
            } catch (PackageManager.NameNotFoundException e) {
                // Continue
            }
        }

        // Check for randomly named Magisk (a.b, a.c pattern)
        return checkRandomNamedMagisk();
    }

    /**
     * Check for randomly named Magisk Manager
     */
    private boolean checkRandomNamedMagisk() {
        try {
            PackageManager pm = context.getPackageManager();
            java.util.List<android.content.pm.PackageInfo> packages = pm.getInstalledPackages(0);

            for (android.content.pm.PackageInfo pkg : packages) {
                String name = pkg.packageName;
                // Pattern: single letter dot single letter (a.b, a.c, etc.)
                if (name.matches("^[a-z]\\.[a-z]$")) {
                    // Verify it has Magisk database
                    if (checkMagiskDatabaseForPackage(name)) {
                        Log.d(TAG, "Found hidden Magisk: " + name);
                        return true;
                    }
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Error checking random names", e);
        }
        return false;
    }

    /**
     * Check if package has Magisk database
     */
    private boolean checkMagiskDatabaseForPackage(String packageName) {
        try {
            PackageManager pm = context.getPackageManager();
            android.content.pm.ApplicationInfo info = pm.getApplicationInfo(packageName, 0);
            String dataDir = info.dataDir;

            String dbPath = dataDir + "/databases/magisk.db";
            return new File(dbPath).exists();
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Check for Magisk core files (ADB location)
     */
    private boolean checkMagiskFiles() {
        String[] criticalPaths = {
                "/data/adb/magisk",
                "/data/adb/magisk.db"
        };

        for (String path : criticalPaths) {
            try {
                File file = new File(path);
                if (file.exists()) {
                    Log.d(TAG, "Found Magisk file: " + path);
                    return true;
                }
            } catch (Exception e) {
                // Access denied - normal
            }
        }
        return false;
    }

    /**
     * Check for Magisk daemon process
     */
    private boolean checkMagiskDaemon() {
        try {
            Process process = Runtime.getRuntime().exec("ps -A");
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream())
            );
            String line;

            while ((line = reader.readLine()) != null) {
                // Only check for exact daemon names
                if (line.contains("magiskd") || line.contains("magiskinit")) {
                    reader.close();
                    process.destroy();
                    Log.d(TAG, "Found Magisk daemon");
                    return true;
                }
            }

            reader.close();
            process.destroy();
        } catch (Exception e) {
            // Normal failure
        }
        return false;
    }

    /**
     * Check /proc/mounts for Magisk mounts
     */
    private boolean checkMagiskMount() {
        try {
            BufferedReader reader = new BufferedReader(new FileReader("/proc/mounts"));
            String line;

            while ((line = reader.readLine()) != null) {
                // Only match explicit "magisk" in mount
                if (line.contains("magisk")) {
                    reader.close();
                    Log.d(TAG, "Found Magisk mount");
                    return true;
                }
            }
            reader.close();
        } catch (Exception e) {
            // Normal failure
        }
        return false;
    }

    /**
     * Check for Zygisk (Magisk's Zygote module)
     */
    private boolean checkZygisk() {
        try {
            BufferedReader reader = new BufferedReader(new FileReader("/proc/self/maps"));
            String line;

            while ((line = reader.readLine()) != null) {
                if (line.toLowerCase().contains("zygisk")) {
                    reader.close();
                    Log.d(TAG, "Found Zygisk");
                    return true;
                }
            }
            reader.close();
        } catch (Exception e) {
            // Normal failure
        }
        return false;
    }

    /**
     * Advanced detection - check /proc/self/mountinfo (more detailed)
     */
    public boolean checkAdvancedMounts() {
        try {
            BufferedReader reader = new BufferedReader(new FileReader("/proc/self/mountinfo"));
            String line;

            while ((line = reader.readLine()) != null) {
                // Check for Magisk overlay mounts
                if (line.contains("magisk") ||
                        (line.contains("overlay") && line.contains("/sbin"))) {
                    reader.close();
                    Log.d(TAG, "Found advanced Magisk mount");
                    return true;
                }
            }
            reader.close();
        } catch (Exception e) {
            // Normal
        }
        return false;
    }

    /**
     * Check for Magisk modules (strong indicator)
     */
    public boolean checkMagiskModules() {
        try {
            File modulesDir = new File("/data/adb/modules");
            if (modulesDir.exists() && modulesDir.isDirectory()) {
                String[] modules = modulesDir.list();
                if (modules != null && modules.length > 0) {
                    Log.d(TAG, "Found " + modules.length + " Magisk modules");
                    return true;
                }
            }
        } catch (Exception e) {
            // Access denied
        }
        return false;
    }
}