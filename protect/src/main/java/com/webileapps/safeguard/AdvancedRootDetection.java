package com.webileapps.safeguard;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.util.List;

public class AdvancedRootDetection {
    private static final String TAG = "RootDetection";
    private final Context context;

    // Confidence scoring system
    private int suspicionScore = 0;
    private static final int THRESHOLD = 3; // Need 3+ indicators to confirm root

    public AdvancedRootDetection(Context context) {
        this.context = context;
    }
    public boolean isDeviceRooted() {
        suspicionScore = 0;

        // High confidence checks (score 3+ = instant detection)
        if (checkSuBinary()) suspicionScore += 3;
        if (checkRootManagementApps()) suspicionScore += 3;
        if (checkMagiskCore()) suspicionScore += 3;

        // Medium confidence checks (score 2 each)
        if (checkDangerousSystemProperties()) suspicionScore += 2;
        if (checkSuspiciousPackages()) suspicionScore += 2;
        if (checkAdvancedMagisk()) suspicionScore += 2;

        // Low confidence checks (score 1 each)
        if (checkTestKeys()) suspicionScore += 1;
        if (checkRootCloakingApps()) suspicionScore += 1;
        if (checkBusyBox()) suspicionScore += 1;

        Log.d(TAG, "Root suspicion score: " + suspicionScore);
        return suspicionScore >= THRESHOLD;
    }

    /**
     * Check for su binary in common locations
     * HIGH CONFIDENCE - Direct evidence of root
     */
    private boolean checkSuBinary() {
        String[] suPaths = {
                "/system/bin/su",
                "/system/xbin/su",
                "/sbin/su",
                "/data/local/xbin/su",
                "/data/local/bin/su",
                "/su/bin/su",
                "/system/sd/xbin/su",
                "/system/bin/failsafe/su",
                "/data/local/su"
        };

        for (String path : suPaths) {
            try {
                File file = new File(path);
                if (file.exists() && canExecuteSu(path)) {
                    Log.d(TAG, "Found su binary at: " + path);
                    return true;
                }
            } catch (Exception e) {
                // File system access blocked - this is actually normal
            }
        }
        return false;
    }

    /**
     * Try to execute su command
     */
    private boolean canExecuteSu(String path) {
        Process process = null;
        try {
            process = Runtime.getRuntime().exec(new String[]{path, "-v"});
            boolean completed = process.waitFor(1, java.util.concurrent.TimeUnit.SECONDS);
            if (completed && process.exitValue() == 0) {
                return true;
            }
        } catch (Exception e) {
            // Expected on non-rooted devices
        } finally {
            if (process != null) {
                try {
                    process.destroy();
                } catch (Exception ignored) {}
            }
        }
        return false;
    }

    /**
     * Check for root management apps (Magisk, SuperSU, KernelSU)
     * HIGH CONFIDENCE
     */
    private boolean checkRootManagementApps() {
        String[] rootApps = {
                "com.topjohnwu.magisk",           // Magisk official
                "com.topjohnwu.magisk.canary",    // Magisk canary
                "io.github.huskydg.magisk",       // Magisk Delta
                "io.github.vvb2060.magisk",       // Magisk Alpha
                "com.koushikdutta.superuser",     // SuperSU
                "eu.chainfire.supersu",           // SuperSU
                "me.weishu.kernelsu",             // KernelSU
                "com.android.magisk"              // Renamed Magisk
        };

        PackageManager pm = context.getPackageManager();
        for (String pkg : rootApps) {
            try {
                pm.getPackageInfo(pkg, 0);
                Log.d(TAG, "Found root app: " + pkg);
                return true;
            } catch (PackageManager.NameNotFoundException e) {
                // App not found - this is normal
            }
        }
        return false;
    }

    /**
     * Check for Magisk core files and directories
     * HIGH CONFIDENCE
     */
    private boolean checkMagiskCore() {
        String[] magiskPaths = {
                "/data/adb/magisk",
                "/data/adb/modules",
                "/data/adb/magisk.db",
                "/sbin/.magisk",
                "/cache/.magisk"
        };

        for (String path : magiskPaths) {
            try {
                File file = new File(path);
                if (file.exists()) {
                    // Additional verification - check if it's actually Magisk
                    if (path.contains("modules")) {
                        File modulesDir = new File(path);
                        if (modulesDir.isDirectory() && modulesDir.list() != null) {
                            String[] modules = modulesDir.list();
                            if (modules != null && modules.length > 0) {
                                Log.d(TAG, "Found Magisk modules at: " + path);
                                return true;
                            }
                        }
                    } else {
                        Log.d(TAG, "Found Magisk file at: " + path);
                        return true;
                    }
                }
            } catch (Exception e) {
                // Access denied - normal on non-rooted devices
            }
        }
        return false;
    }

    /**
     * Check dangerous system properties
     * MEDIUM CONFIDENCE - Can have false positives on custom ROMs
     */
    private boolean checkDangerousSystemProperties() {
        // Only check critical properties that rarely have false positives
        String debuggable = getSystemProperty("ro.debuggable");
        String secure = getSystemProperty("ro.secure");

        // ro.debuggable=1 AND ro.secure=0 is strong indicator
        boolean isDangerous = "1".equals(debuggable) && "0".equals(secure);

        if (isDangerous) {
            Log.d(TAG, "Dangerous system properties detected");
        }

        return isDangerous;
    }

    /**
     * Check for suspicious single-letter packages (Magisk hiding)
     * MEDIUM CONFIDENCE
     */
    private boolean checkSuspiciousPackages() {
        try {
            PackageManager pm = context.getPackageManager();
            List<PackageInfo> packages = pm.getInstalledPackages(0);

            for (android.content.pm.PackageInfo pkg : packages) {
                String name = pkg.packageName;
                // Single letter packages: a.b, a.c, etc.
                if (name.matches("^[a-z]\\.[a-z]$")) {
                    // Verify it has suspicious characteristics
                    if (hasRootCharacteristics(pm, name)) {
                        Log.d(TAG, "Found suspicious package: " + name);
                        return true;
                    }
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Error checking packages", e);
        }
        return false;
    }

    /**
     * Verify if a package has root-like characteristics
     */
    private boolean hasRootCharacteristics(PackageManager pm, String packageName) {
        try {
            ApplicationInfo info = pm.getApplicationInfo(packageName, 0);

            // Check if it's a system app (shouldn't be for single-letter packages)
            boolean isSystemApp = (info.flags & ApplicationInfo.FLAG_SYSTEM) != 0;

            // Check for dangerous permissions
            String[] dangerousPerms = {
                    "android.permission.ACCESS_SUPERUSER",
                    "android.permission.MOUNT_UNMOUNT_FILESYSTEMS"
            };

            for (String perm : dangerousPerms) {
                if (pm.checkPermission(perm, packageName) == PackageManager.PERMISSION_GRANTED) {
                    return true;
                }
            }

            // Single letter package that's not a system app is suspicious
            return !isSystemApp;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Advanced Magisk detection (memory maps, processes)
     * MEDIUM CONFIDENCE
     */
    private boolean checkAdvancedMagisk() {
        return checkMagiskInMaps() || checkMagiskProcess();
    }

    private boolean checkMagiskInMaps() {
        try {
            BufferedReader reader = new BufferedReader(new FileReader("/proc/self/maps"));
            String line;

            while ((line = reader.readLine()) != null) {
                String lower = line.toLowerCase();
                // Only check for strong Magisk indicators
                if (lower.contains("magisk") || lower.contains("zygisk")) {
                    reader.close();
                    Log.d(TAG, "Found Magisk in memory maps");
                    return true;
                }
            }
            reader.close();
        } catch (Exception e) {
            // Normal on most devices
        }
        return false;
    }

    private boolean checkMagiskProcess() {
        try {
            Process process = Runtime.getRuntime().exec("ps");
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream())
            );
            String line;

            String[] magiskProcesses = {"magiskd", "magiskinit", "zygiskd"};

            while ((line = reader.readLine()) != null) {
                String lower = line.toLowerCase();
                for (String proc : magiskProcesses) {
                    if (lower.contains(proc)) {
                        reader.close();
                        process.destroy();
                        Log.d(TAG, "Found Magisk process: " + proc);
                        return true;
                    }
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
     * Check for test-keys (custom ROM indicator)
     * LOW CONFIDENCE - Many custom ROMs use test-keys
     */
    private boolean checkTestKeys() {
        try {
            String buildTags = Build.TAGS;
            if (buildTags != null && buildTags.contains("test-keys")) {
                Log.d(TAG, "Device has test-keys");
                return true;
            }
        } catch (Exception e) {
            // Ignore
        }
        return false;
    }

    /**
     * Check for root cloaking apps
     * LOW CONFIDENCE - Presence doesn't guarantee root
     */
    private boolean checkRootCloakingApps() {
        String[] cloakApps = {
                "com.devadvance.rootcloak",
                "com.devadvance.rootcloakplus",
                "com.amphoras.hidemyroot",
                "com.formyhm.hideroot"
        };

        PackageManager pm = context.getPackageManager();
        for (String pkg : cloakApps) {
            try {
                pm.getPackageInfo(pkg, 0);
                Log.d(TAG, "Found root cloak app: " + pkg);
                return true;
            } catch (PackageManager.NameNotFoundException e) {
                // Not found - normal
            }
        }
        return false;
    }

    /**
     * Check for BusyBox
     * LOW CONFIDENCE - Many legitimate apps use BusyBox
     */
    private boolean checkBusyBox() {
        String[] paths = {
                "/system/bin/busybox",
                "/system/xbin/busybox"
        };

        for (String path : paths) {
            try {
                if (new File(path).exists()) {
                    Log.d(TAG, "Found BusyBox at: " + path);
                    return true;
                }
            } catch (Exception e) {
                // Normal
            }
        }
        return false;
    }

    /**
     * Get system property value
     */
    private String getSystemProperty(String key) {
        try {
            Process process = Runtime.getRuntime().exec("getprop " + key);
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream())
            );
            String value = reader.readLine();
            reader.close();

            boolean finished = process.waitFor(2, java.util.concurrent.TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                return null;
            }

            return value != null ? value.trim() : null;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Get detailed root detection report
     */
    public String getDetectionReport() {
        StringBuilder report = new StringBuilder();
        report.append("Root Detection Report\n");
        report.append("=====================\n");
        report.append("Total Score: ").append(suspicionScore).append("/").append(THRESHOLD).append("\n");
        report.append("Device: ").append(Build.MODEL).append("\n");
        report.append("Android: ").append(Build.VERSION.RELEASE).append("\n");
        report.append("Build Tags: ").append(Build.TAGS).append("\n");
        return report.toString();
    }

    /**
     * Check if running on emulator
     * Separate from root detection
     */
    public boolean isEmulator() {
        int emulatorScore = 0;

        try {
            // Check Build properties (score 2 each for strong indicators)
            if (Build.FINGERPRINT.startsWith("generic") ||
                Build.FINGERPRINT.startsWith("unknown") ||
                Build.FINGERPRINT.contains("test-keys")) {
                emulatorScore += 2;
            }

            if (Build.MODEL.contains("google_sdk") ||
                Build.MODEL.contains("Emulator") ||
                Build.MODEL.contains("Android SDK built for")) {
                emulatorScore += 2;
            }

            if (Build.MANUFACTURER.contains("Genymotion") ||
                Build.HARDWARE.contains("goldfish") ||
                Build.HARDWARE.contains("ranchu") ||
                Build.HARDWARE.contains("vbox")) {
                emulatorScore += 3; // Strong indicator
            }

            if (Build.PRODUCT.contains("sdk") ||
                Build.PRODUCT.contains("sdk_gphone") ||
                Build.PRODUCT.contains("sdk_google") ||
                Build.PRODUCT.contains("vbox86p") ||
                Build.PRODUCT.contains("emulator")) {
                emulatorScore += 2;
            }

            // Check for generic build
            if ((Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic"))) {
                emulatorScore += 2;
            }

            // Check BOARD
            if (Build.BOARD.contains("goldfish") ||
                Build.BOARD.contains("ranchu") ||
                Build.BOARD.contains("vbox")) {
                emulatorScore += 2;
            }

            // Check specific emulator files (score 3 - very strong)
            if (checkEmulatorFiles()) {
                emulatorScore += 3;
            }

            // Check for emulator-specific properties
            if (checkEmulatorProperties()) {
                emulatorScore += 2;
            }

            // Check for Genymotion
            if (checkGenymotion()) {
                emulatorScore += 3;
            }

            Log.d(TAG, "Emulator detection score: " + emulatorScore);

            // Require score of 3+ to be confident it's an emulator
            return emulatorScore >= 3;

        } catch (Exception e) {
            Log.e(TAG, "Error in emulator detection", e);
            return false;
        }
    }

    /**
     * Check for emulator-specific files
     */
    private boolean checkEmulatorFiles() {
        String[] emulatorFiles = {
            "/dev/socket/qemud",
            "/dev/qemu_pipe",
            "/system/lib/libc_malloc_debug_qemu.so",
            "/sys/qemu_trace",
            "/system/bin/qemu-props"
        };

        for (String file : emulatorFiles) {
            try {
                if (new File(file).exists()) {
                    Log.d(TAG, "Found emulator file: " + file);
                    return true;
                }
            } catch (Exception e) {
                // Continue checking
            }
        }
        return false;
    }

    /**
     * Check emulator-specific system properties
     */
    private boolean checkEmulatorProperties() {
        String qemu = getSystemProperty("ro.kernel.qemu");
        if ("1".equals(qemu)) {
            Log.d(TAG, "QEMU property detected");
            return true;
        }

        String hardware = getSystemProperty("ro.hardware");
        if (hardware != null && (hardware.contains("goldfish") ||
                                 hardware.contains("ranchu") ||
                                 hardware.contains("vbox"))) {
            Log.d(TAG, "Emulator hardware detected: " + hardware);
            return true;
        }

        String serialno = getSystemProperty("ro.serialno");
        if (serialno != null && serialno.toLowerCase().contains("emulator")) {
            Log.d(TAG, "Emulator serial number detected");
            return true;
        }

        return false;
    }

    /**
     * Check for Genymotion emulator
     */
    private boolean checkGenymotion() {
        try {
            String buildProduct = Build.PRODUCT;
            if (buildProduct != null && buildProduct.contains("vbox")) {
                return true;
            }

            File genymotionFile = new File("/dev/socket/genyd");
            if (genymotionFile.exists()) {
                Log.d(TAG, "Genymotion detected");
                return true;
            }

            String[] genymotionFiles = {
                "/system/bin/genymotion",
                "/system/lib/libgenymotion.so"
            };

            for (String file : genymotionFiles) {
                if (new File(file).exists()) {
                    Log.d(TAG, "Found Genymotion file: " + file);
                    return true;
                }
            }
        } catch (Exception e) {
            // Continue
        }
        return false;
    }
}