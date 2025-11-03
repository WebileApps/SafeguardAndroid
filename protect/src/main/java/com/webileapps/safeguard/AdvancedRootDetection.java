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

    private int suspicionScore = 0;
    private static final int THRESHOLD = 5; // Increased threshold for more checks

    public AdvancedRootDetection(Context context) {
        this.context = context;
    }
    public boolean isDeviceRooted() {
        suspicionScore = 0;
        if (checkSuBinary()) suspicionScore += 5;
        if (checkRootManagementApps()) suspicionScore += 5;
        if (checkMagiskCore()) suspicionScore += 5;
        if (checkMagiskSuList()) suspicionScore += 5;
        if (checkMagiskFileDescriptors()) suspicionScore += 5;
        if (checkShamikoModule()) suspicionScore += 5;
        if (checkDangerousSystemProperties()) suspicionScore += 3;
        if (checkSuspiciousPackages()) suspicionScore += 3;
        if (checkAdvancedMagisk()) suspicionScore += 3;
        if (checkMagiskSocketConnections()) suspicionScore += 3;
        if (checkZygiskDetection()) suspicionScore += 3;
        if (checkMagiskMounts()) suspicionScore += 3;
        if (checkMagiskTmpfs()) suspicionScore += 3;
        if (checkMagiskOverlays()) suspicionScore += 3;
        if (checkSuDaemonSocket()) suspicionScore += 3;
        if (checkSELinuxPermissive()) suspicionScore += 3;
        if (checkMountNamespaceManipulation()) suspicionScore += 3;
        if (checkTestKeys()) suspicionScore += 2;
        if (checkRootCloakingApps()) suspicionScore += 2;
        if (checkBusyBox()) suspicionScore += 2;
        if (detectNativeLibraryHooks()) suspicionScore += 2;
        if (checkProcessCapabilities()) suspicionScore += 2;
        if (checkMagiskInotify()) suspicionScore += 2;
        if (checkNativeBridgeInjection()) suspicionScore += 2;
        if (checkMagiskHiddenApps()) suspicionScore += 2;
        if (checkSuspiciousLatency()) suspicionScore += 1;

        Log.d(TAG, "Root suspicion score: " + suspicionScore + " (threshold: " + THRESHOLD + ")");
        return suspicionScore >= THRESHOLD;
    }

    /**
     * ENHANCED: Check for su binary with multiple detection methods
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
                "/data/local/su",
                "/vendor/bin/su"  // NEW
        };

        for (String path : suPaths) {
            try {
                File file = new File(path);

                // Check 1: File exists
                if (file.exists()) {
                    Log.d(TAG, "Found su binary at: " + path);
                    return true;
                }

                // Check 2: File is executable (NEW)
                if (file.canExecute()) {
                    Log.d(TAG, "Found executable su at: " + path);
                    return true;
                }

                // Check 3: Try to execute (ENHANCED with multiple commands)
                if (canExecuteSuEnhanced(path)) {
                    return true;
                }

                // Check 4: Check if it's a symlink (NEW)
                if (checkSymlink(path)) {
                    return true;
                }

            } catch (Exception e) {
                // File system access blocked
            }
        }

        // Check 5: Check su in PATH (NEW)
        if (checkSuInPath()) {
            return true;
        }

        return false;
    }
    private boolean canExecuteSuEnhanced(String path) {
        String[] commands = {
                path + " -v",
                path + " -c id",
                path + " -c exit"
        };

        for (String cmd : commands) {
            Process process = null;
            try {
                process = Runtime.getRuntime().exec(cmd);
                boolean completed = process.waitFor(1, java.util.concurrent.TimeUnit.SECONDS);
                if (completed && process.exitValue() == 0) {
                    Log.d(TAG, "Su execution succeeded: " + cmd);
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
        }
        return false;
    }

    /**
     * Original method kept for compatibility
     */
    private boolean canExecuteSu(String path) {
        return canExecuteSuEnhanced(path);
    }

    /**
     * NEW: Check if file is a symbolic link
     */
    private boolean checkSymlink(String path) {
        try {
            File file = new File(path);
            if (file.exists()) {
                String canonical = file.getCanonicalPath();
                String absolute = file.getAbsolutePath();
                if (!canonical.equals(absolute)) {
                    Log.d(TAG, "Found su symlink: " + path + " -> " + canonical);
                    return true;
                }
            }
        } catch (Exception e) {
            // Normal
        }
        return false;
    }

    /**
     * NEW: Check for su in PATH environment variable
     */
    private boolean checkSuInPath() {
        try {
            Process process = Runtime.getRuntime().exec("which su");
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream())
            );
            String result = reader.readLine();
            reader.close();

            boolean finished = process.waitFor(2, java.util.concurrent.TimeUnit.SECONDS);
            process.destroy();

            if (result != null && !result.isEmpty()) {
                Log.d(TAG, "Found su in PATH: " + result);
                return true;
            }
        } catch (Exception e) {
            // Normal failure
        }
        return false;
    }

    private boolean checkRootManagementApps() {
        String[] rootApps = {
                "com.topjohnwu.magisk",
                "com.topjohnwu.magisk.canary",
                "io.github.huskydg.magisk",
                "io.github.vvb2060.magisk",
                "com.koushikdutta.superuser",
                "eu.chainfire.supersu",
                "me.weishu.kernelsu",
                "com.android.magisk"
        };

        PackageManager pm = context.getPackageManager();
        for (String pkg : rootApps) {
            try {
                pm.getPackageInfo(pkg, 0);
                Log.d(TAG, "Found root app: " + pkg);
                return true;
            } catch (PackageManager.NameNotFoundException e) {
                // App not found
            }
        }
        return false;
    }

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
                // Access denied
            }
        }
        return false;
    }

    private boolean checkDangerousSystemProperties() {
        String debuggable = getSystemProperty("ro.debuggable");
        String secure = getSystemProperty("ro.secure");

        boolean isDangerous = "1".equals(debuggable) && "0".equals(secure);

        if (isDangerous) {
            Log.d(TAG, "Dangerous system properties detected");
        }

        return isDangerous;
    }

    /**
     * ENHANCED: Check suspicious packages with better trait detection
     */
    private boolean checkSuspiciousPackages() {
        try {
            PackageManager pm = context.getPackageManager();
            List<PackageInfo> packages = pm.getInstalledPackages(0);

            for (PackageInfo pkg : packages) {
                String name = pkg.packageName;

                // Pattern 1: Single letter (a.b, a.c)
                // Pattern 2: Two letters (ab.cd) - NEW
                // Pattern 3: Short com packages (com.ab) - NEW
                if (name.matches("^[a-z]\\.[a-z]$") ||
                        name.matches("^[a-z]{2}\\.[a-z]{2}$") ||
                        name.matches("^com\\.[a-z]{2,4}$")) {

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
     * ENHANCED: Better root characteristics detection
     */
    private boolean hasRootCharacteristics(PackageManager pm, String packageName) {
        try {
            ApplicationInfo info = pm.getApplicationInfo(packageName, 0);
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

            // NEW: Check app data directory for Magisk files
            if (checkMagiskFilesInPackage(info)) {
                return true;
            }

            return !isSystemApp;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * NEW: Check for Magisk files in app data directory
     */
    private boolean checkMagiskFilesInPackage(ApplicationInfo info) {
        String appDataPath = info.dataDir;
        String[] magiskFiles = {
                "databases/magisk.db",
                "shared_prefs/config.xml",
                "files/busybox"
        };

        for (String file : magiskFiles) {
            if (new File(appDataPath + "/" + file).exists()) {
                Log.d(TAG, "Found Magisk file in app: " + appDataPath);
                return true;
            }
        }
        return false;
    }

    /**
     * ENHANCED: More comprehensive Magisk detection
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
                if (lower.contains("magisk") || lower.contains("zygisk") ||
                        lower.contains("libzygisk")) {  // NEW: libzygisk check
                    reader.close();
                    Log.d(TAG, "Found Magisk in memory maps");
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
     * ENHANCED: Try multiple process listing commands
     */
    private boolean checkMagiskProcess() {
        String[] commands = {"ps -A", "ps", "ps -ef"};  // NEW: Multiple variations

        for (String cmd : commands) {
            try {
                Process process = Runtime.getRuntime().exec(cmd);
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
                // Try next command
            }
        }
        return false;
    }

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
                // Not found
            }
        }
        return false;
    }

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

    // ==================== NEW METHODS (Missing from Original) ====================

    /**
     * NEW: Check Magisk's sulist and config files
     * CRITICAL - These exist even with DenyList enabled
     */
    private boolean checkMagiskSuList() {
        String[] suListPaths = {
                "/data/adb/.magisk/config",
                "/data/adb/magisk/magisk.db",
                "/data/user_de/0/com.topjohnwu.magisk/databases/magisk.db",
                "/data/adb/ksu/ksud",
                "/data/adb/ap/apsud"
        };

        for (String path : suListPaths) {
            try {
                File file = new File(path);
                if (file.exists() && file.canRead()) {
                    Log.d(TAG, "Found Magisk sulist: " + path);
                    return true;
                }
            } catch (Exception ignored) {
            }
        }
        return false;
    }

    /**
     * NEW: Check /proc/self/fd for Magisk file descriptors
     * Very reliable - hard to hide open file descriptors
     */
    private boolean checkMagiskFileDescriptors() {
        try {
            File fdDir = new File("/proc/self/fd");
            File[] fds = fdDir.listFiles();

            if (fds != null) {
                for (File fd : fds) {
                    try {
                        String link = fd.getCanonicalPath();
                        if (link.contains("magisk") ||
                                link.contains("/sbin") ||
                                link.contains("/dev/magisk") ||
                                link.contains("libmagisk")) {
                            Log.d(TAG, "Found Magisk file descriptor: " + link);
                            return true;
                        }
                    } catch (Exception ignored) {
                    }
                }
            }
        } catch (Exception e) {
            // Access denied
        }
        return false;
    }

    /**
     * NEW: Check for Shamiko module
     * Shamiko specifically enhances Magisk hiding - strong indicator
     */
    private boolean checkShamikoModule() {
        String[] shamikoTraces = {
                "/data/adb/modules/zygisk_shamiko",
                "/data/adb/modules/shamiko",
                "/system/lib/libshamiko.so",
                "/system/lib64/libshamiko.so"
        };

        for (String path : shamikoTraces) {
            try {
                if (new File(path).exists()) {
                    Log.d(TAG, "Shamiko module detected: " + path);
                    return true;
                }
            } catch (Exception e) {
                // Continue
            }
        }
        return false;
    }

    /**
     * NEW: Check /proc/net/unix for Magisk socket connections
     */
    private boolean checkMagiskSocketConnections() {
        try {
            File netUnix = new File("/proc/net/unix");
            if (netUnix.exists()) {
                BufferedReader reader = new BufferedReader(new FileReader(netUnix));
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.contains("magisk") ||
                            line.contains("zygisk") ||
                            line.contains("/dev/socket/magisk")) {
                        reader.close();
                        Log.d(TAG, "Found Magisk socket");
                        return true;
                    }
                }
                reader.close();
            }
        } catch (Exception e) {
            // Normal failure
        }
        return false;
    }

    /**
     * NEW: Enhanced Zygisk detection
     */
    private boolean checkZygiskDetection() {
        try {
            // Check memory maps
            File mapsFile = new File("/proc/self/maps");
            if (mapsFile.exists()) {
                BufferedReader reader = new BufferedReader(new FileReader(mapsFile));
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.contains("zygisk") ||
                            line.contains("libzygisk") ||
                            line.contains("zygote-loader")) {
                        reader.close();
                        Log.d(TAG, "Found Zygisk in maps");
                        return true;
                    }
                }
                reader.close();
            }

            // Check environment variable
            String zygiskEnv = System.getenv("ZYGISK_ENABLED");
            if (zygiskEnv != null && zygiskEnv.equals("1")) {
                Log.d(TAG, "Zygisk environment variable detected");
                return true;
            }

        } catch (Exception e) {
            // Normal failure
        }
        return false;
    }

    /**
     * NEW: Check /proc/mounts for Magisk
     */
    private boolean checkMagiskMounts() {
        try {
            BufferedReader reader = new BufferedReader(new FileReader("/proc/mounts"));
            String line;

            while ((line = reader.readLine()) != null) {
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
     * NEW: Check /proc/self/mountinfo for tmpfs mounts
     */
    private boolean checkMagiskTmpfs() {
        try {
            BufferedReader reader = new BufferedReader(new FileReader("/proc/self/mountinfo"));
            String line;

            while ((line = reader.readLine()) != null) {
                if (line.contains("tmpfs") &&
                        (line.contains("/sbin") ||
                                line.contains("magisk") ||
                                line.contains("/dev/magisk"))) {
                    reader.close();
                    Log.d(TAG, "Found Magisk tmpfs mount");
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
     * NEW: Check for Magisk overlay mounts
     */
    private boolean checkMagiskOverlays() {
        try {
            String[] overlayPaths = {
                    "/sbin/.magisk/mirror",
                    "/sbin/.magisk/modules",
                    "/dev/.magisk/modules"
            };

            for (String path : overlayPaths) {
                if (new File(path).exists()) {
                    Log.d(TAG, "Found Magisk overlay: " + path);
                    return true;
                }
            }

            BufferedReader reader = new BufferedReader(new FileReader("/proc/self/mountinfo"));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("overlay") && line.contains("magisk")) {
                    reader.close();
                    Log.d(TAG, "Found Magisk overlay mount");
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
     * NEW: Check for su daemon socket
     */
    private boolean checkSuDaemonSocket() {
        String[] socketPaths = {
                "/dev/socket/magiskd",
                "/dev/socket/su",
                "/dev/.socket/magisk"
        };

        for (String path : socketPaths) {
            try {
                if (new File(path).exists()) {
                    Log.d(TAG, "Found su daemon socket: " + path);
                    return true;
                }
            } catch (Exception e) {
                // Access denied
            }
        }
        return false;
    }

    /**
     * NEW: Check SELinux enforcement status
     */
    private boolean checkSELinuxPermissive() {
        try {
            File selinuxFile = new File("/sys/fs/selinux/enforce");
            if (selinuxFile.exists()) {
                BufferedReader reader = new BufferedReader(new FileReader(selinuxFile));
                String mode = reader.readLine();
                reader.close();

                // 0 = permissive (suspicious), 1 = enforcing (normal)
                if ("0".equals(mode)) {
                    Log.d(TAG, "SELinux is in permissive mode");
                    return true;
                }
            }
        } catch (Exception e) {
            // Normal failure
        }
        return false;
    }

    /**
     * NEW: Check for mount namespace manipulation
     */
    private boolean checkMountNamespaceManipulation() {
        try {
            File selfNs = new File("/proc/self/ns/mnt");
            File initNs = new File("/proc/1/ns/mnt");

            if (selfNs.exists() && initNs.exists()) {
                String selfLink = selfNs.getCanonicalPath();
                String initLink = initNs.getCanonicalPath();

                if (!selfLink.equals(initLink)) {
                    Log.d(TAG, "Mount namespace manipulation detected");
                    return true;
                }
            }
        } catch (Exception e) {
            // Normal failure
        }
        return false;
    }

    /**
     * NEW: Detect native library hooks
     */
    private boolean detectNativeLibraryHooks() {
        try {
            File mapsFile = new File("/proc/self/maps");
            BufferedReader reader = new BufferedReader(new FileReader(mapsFile));
            String line;

            while ((line = reader.readLine()) != null) {
                if (line.contains("libc.so") &&
                        (line.contains(" rw-") || line.contains(" rwx"))) {
                    reader.close();
                    Log.d(TAG, "Suspicious writable libc section");
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
     * NEW: Check process capabilities
     */
    private boolean checkProcessCapabilities() {
        try {
            File statusFile = new File("/proc/self/status");
            if (statusFile.exists()) {
                BufferedReader reader = new BufferedReader(new FileReader(statusFile));
                String line;

                while ((line = reader.readLine()) != null) {
                    if (line.startsWith("CapEff:") || line.startsWith("CapPrm:")) {
                        String caps = line.split(":")[1].trim();
                        if (!caps.equals("0000000000000000")) {
                            Log.d(TAG, "Suspicious capabilities: " + line);
                            reader.close();
                            return true;
                        }
                    }
                }
                reader.close();
            }
        } catch (Exception e) {
            // Normal failure
        }
        return false;
    }

    /**
     * NEW: Check for inotify watches
     */
    private boolean checkMagiskInotify() {
        try {
            File fdInfo = new File("/proc/self/fdinfo");
            if (fdInfo.exists() && fdInfo.isDirectory()) {
                File[] files = fdInfo.listFiles();
                if (files != null) {
                    for (File file : files) {
                        BufferedReader reader = new BufferedReader(new FileReader(file));
                        String line;
                        while ((line = reader.readLine()) != null) {
                            if (line.contains("inotify") &&
                                    (line.contains("magisk") || line.contains("/sbin"))) {
                                reader.close();
                                Log.d(TAG, "Found Magisk inotify watch");
                                return true;
                            }
                        }
                        reader.close();
                    }
                }
            }
        } catch (Exception e) {
            // Access denied
        }
        return false;
    }

    /**
     * NEW: Check for native bridge injection
     */
    private boolean checkNativeBridgeInjection() {
        try {
            String nativeBridge = System.getProperty("ro.dalvik.vm.native.bridge");
            if (nativeBridge != null && !nativeBridge.isEmpty() &&
                    !nativeBridge.equals("0")) {
                Log.d(TAG, "Native bridge detected: " + nativeBridge);
                return true;
            }
        } catch (Exception e) {
            // Normal failure
        }
        return false;
    }

    /**
     * NEW: Check for hidden apps
     */
    private boolean checkMagiskHiddenApps() {
        try {
            PackageManager pm = context.getPackageManager();
            List<PackageInfo> packages = pm.getInstalledPackages(0);
            int pmCount = packages.size();

            File dataApp = new File("/data/app");
            int fileCount = 0;
            if (dataApp.exists() && dataApp.isDirectory()) {
                File[] apps = dataApp.listFiles();
                if (apps != null) {
                    fileCount = apps.length;
                }
            }

            if (Math.abs(pmCount - fileCount) > 5) {
                Log.d(TAG, "Package count mismatch detected");
                return true;
            }
        } catch (Exception e) {
            // Access denied
        }
        return false;
    }

    /**
     * NEW: Timing-based detection
     */
    private boolean checkSuspiciousLatency() {
        try {
            long startTime = System.nanoTime();
            File file = new File("/system/bin/su");
            boolean exists = file.exists();
            long endTime = System.nanoTime();

            long duration = endTime - startTime;

            if (duration > 5_000_000) { // 5ms
                Log.d(TAG, "Suspicious latency: " + (duration / 1_000_000) + "ms");
                return true;
            }
        } catch (Exception e) {
            // Normal failure
        }
        return false;
    }

    // ==================== UTILITY METHODS ====================

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
        report.append("Build Tags: ").append(Build.TAGS).append("\n\n");

        report.append("Detection Methods Triggered:\n");
        report.append("============================\n");

        if (checkSuBinary()) report.append("✓ SU Binary Found\n");
        if (checkRootManagementApps()) report.append("✓ Root Management App\n");
        if (checkMagiskCore()) report.append("✓ Magisk Core Files\n");
        if (checkMagiskSuList()) report.append("✓ Magisk SuList\n");
        if (checkMagiskFileDescriptors()) report.append("✓ Magisk File Descriptors\n");
        if (checkShamikoModule()) report.append("✓ Shamiko Module\n");
        if (checkMagiskSocketConnections()) report.append("✓ Magisk Sockets\n");
        if (checkZygiskDetection()) report.append("✓ Zygisk Detected\n");
        if (checkMagiskMounts()) report.append("✓ Magisk Mounts\n");
        if (checkMagiskTmpfs()) report.append("✓ Magisk Tmpfs\n");
        if (checkMagiskOverlays()) report.append("✓ Magisk Overlays\n");
        if (checkSuDaemonSocket()) report.append("✓ SU Daemon Socket\n");
        if (checkSELinuxPermissive()) report.append("✓ SELinux Permissive\n");
        if (checkMountNamespaceManipulation()) report.append("✓ Mount Namespace Manipulation\n");
        if (checkDangerousSystemProperties()) report.append("✓ Dangerous Properties\n");
        if (checkSuspiciousPackages()) report.append("✓ Suspicious Packages\n");
        if (checkTestKeys()) report.append("✓ Test Keys\n");
        if (checkRootCloakingApps()) report.append("✓ Root Cloaking Apps\n");
        if (detectNativeLibraryHooks()) report.append("✓ Native Library Hooks\n");
        if (checkProcessCapabilities()) report.append("✓ Suspicious Capabilities\n");

        return report.toString();
    }

    /**
     * Get detection confidence level
     */
    public String getConfidenceLevel() {
        if (suspicionScore >= 15) return "VERY HIGH";
        if (suspicionScore >= 10) return "HIGH";
        if (suspicionScore >= THRESHOLD) return "MEDIUM";
        return "LOW";
    }

    /**
     * Check if running on emulator (kept from original)
     */
    public boolean isEmulator() {
        int emulatorScore = 0;

        try {
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
                emulatorScore += 3;
            }

            if (Build.PRODUCT.contains("sdk") ||
                    Build.PRODUCT.contains("sdk_gphone") ||
                    Build.PRODUCT.contains("sdk_google") ||
                    Build.PRODUCT.contains("vbox86p") ||
                    Build.PRODUCT.contains("emulator")) {
                emulatorScore += 2;
            }

            if ((Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic"))) {
                emulatorScore += 2;
            }

            if (Build.BOARD.contains("goldfish") ||
                    Build.BOARD.contains("ranchu") ||
                    Build.BOARD.contains("vbox")) {
                emulatorScore += 2;
            }

            if (checkEmulatorFiles()) {
                emulatorScore += 3;
            }

            if (checkEmulatorProperties()) {
                emulatorScore += 2;
            }

            if (checkGenymotion()) {
                emulatorScore += 3;
            }

            Log.d(TAG, "Emulator detection score: " + emulatorScore);
            return emulatorScore >= 3;

        } catch (Exception e) {
            Log.e(TAG, "Error in emulator detection", e);
            return false;
        }
    }

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
                // Continue
            }
        }
        return false;
    }

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

    /**
     * Get comprehensive detection result object
     */
    public DetectionResult getComprehensiveResult() {
        DetectionResult result = new DetectionResult();

        // High confidence indicators
        result.suBinary = checkSuBinary();
        result.rootApps = checkRootManagementApps();
        result.magiskCore = checkMagiskCore();
        result.magiskSuList = checkMagiskSuList();
        result.magiskFileDescriptors = checkMagiskFileDescriptors();
        result.shamiko = checkShamikoModule();

        // Medium confidence indicators
        result.dangerousProps = checkDangerousSystemProperties();
        result.suspiciousPackages = checkSuspiciousPackages();
        result.magiskInMemory = checkMagiskInMaps();
        result.magiskProcess = checkMagiskProcess();
        result.magiskSockets = checkMagiskSocketConnections();
        result.zygisk = checkZygiskDetection();
        result.magiskMounts = checkMagiskMounts();
        result.magiskTmpfs = checkMagiskTmpfs();
        result.magiskOverlays = checkMagiskOverlays();
        result.suDaemonSocket = checkSuDaemonSocket();
        result.selinuxPermissive = checkSELinuxPermissive();
        result.mountNamespace = checkMountNamespaceManipulation();

        // Low confidence indicators
        result.testKeys = checkTestKeys();
        result.rootCloaking = checkRootCloakingApps();
        result.busybox = checkBusyBox();
        result.nativeHooks = detectNativeLibraryHooks();
        result.capabilities = checkProcessCapabilities();
        result.inotify = checkMagiskInotify();
        result.nativeBridge = checkNativeBridgeInjection();
        result.hiddenApps = checkMagiskHiddenApps();
        result.suspiciousLatency = checkSuspiciousLatency();

        result.totalScore = suspicionScore;
        result.isRooted = suspicionScore >= THRESHOLD;
        result.confidenceLevel = getConfidenceLevel();

        return result;
    }

    /**
     * Detection result class
     */
    public static class DetectionResult {
        // High confidence
        public boolean suBinary = false;
        public boolean rootApps = false;
        public boolean magiskCore = false;
        public boolean magiskSuList = false;
        public boolean magiskFileDescriptors = false;
        public boolean shamiko = false;

        // Medium confidence
        public boolean dangerousProps = false;
        public boolean suspiciousPackages = false;
        public boolean magiskInMemory = false;
        public boolean magiskProcess = false;
        public boolean magiskSockets = false;
        public boolean zygisk = false;
        public boolean magiskMounts = false;
        public boolean magiskTmpfs = false;
        public boolean magiskOverlays = false;
        public boolean suDaemonSocket = false;
        public boolean selinuxPermissive = false;
        public boolean mountNamespace = false;

        // Low confidence
        public boolean testKeys = false;
        public boolean rootCloaking = false;
        public boolean busybox = false;
        public boolean nativeHooks = false;
        public boolean capabilities = false;
        public boolean inotify = false;
        public boolean nativeBridge = false;
        public boolean hiddenApps = false;
        public boolean suspiciousLatency = false;

        public int totalScore = 0;
        public boolean isRooted = false;
        public String confidenceLevel = "LOW";

        public int countHighConfidenceIndicators() {
            int count = 0;
            if (suBinary) count++;
            if (rootApps) count++;
            if (magiskCore) count++;
            if (magiskSuList) count++;
            if (magiskFileDescriptors) count++;
            if (shamiko) count++;
            return count;
        }

        public int countMediumConfidenceIndicators() {
            int count = 0;
            if (dangerousProps) count++;
            if (suspiciousPackages) count++;
            if (magiskInMemory) count++;
            if (magiskProcess) count++;
            if (magiskSockets) count++;
            if (zygisk) count++;
            if (magiskMounts) count++;
            if (magiskTmpfs) count++;
            if (magiskOverlays) count++;
            if (suDaemonSocket) count++;
            if (selinuxPermissive) count++;
            if (mountNamespace) count++;
            return count;
        }

        public int countLowConfidenceIndicators() {
            int count = 0;
            if (testKeys) count++;
            if (rootCloaking) count++;
            if (busybox) count++;
            if (nativeHooks) count++;
            if (capabilities) count++;
            if (inotify) count++;
            if (nativeBridge) count++;
            if (hiddenApps) count++;
            if (suspiciousLatency) count++;
            return count;
        }

        @Override
        public String toString() {
            return "DetectionResult{" +
                    "isRooted=" + isRooted +
                    ", score=" + totalScore +
                    ", confidence=" + confidenceLevel +
                    ", highIndicators=" + countHighConfidenceIndicators() +
                    ", mediumIndicators=" + countMediumConfidenceIndicators() +
                    ", lowIndicators=" + countLowConfidenceIndicators() +
                    '}';
        }

        public String getDetailedReport() {
            StringBuilder sb = new StringBuilder();
            sb.append("=== ROOT DETECTION DETAILED REPORT ===\n\n");
            sb.append("Status: ").append(isRooted ? "ROOTED" : "CLEAN").append("\n");
            sb.append("Score: ").append(totalScore).append("\n");
            sb.append("Confidence: ").append(confidenceLevel).append("\n\n");

            if (countHighConfidenceIndicators() > 0) {
                sb.append("HIGH CONFIDENCE INDICATORS (").append(countHighConfidenceIndicators()).append("):\n");
                if (suBinary) sb.append("  ✓ SU Binary Found\n");
                if (rootApps) sb.append("  ✓ Root Management Apps\n");
                if (magiskCore) sb.append("  ✓ Magisk Core Files\n");
                if (magiskSuList) sb.append("  ✓ Magisk SuList/Config\n");
                if (magiskFileDescriptors) sb.append("  ✓ Magisk File Descriptors\n");
                if (shamiko) sb.append("  ✓ Shamiko Module\n");
                sb.append("\n");
            }

            if (countMediumConfidenceIndicators() > 0) {
                sb.append("MEDIUM CONFIDENCE INDICATORS (").append(countMediumConfidenceIndicators()).append("):\n");
                if (dangerousProps) sb.append("  ✓ Dangerous Properties\n");
                if (suspiciousPackages) sb.append("  ✓ Suspicious Packages\n");
                if (magiskInMemory) sb.append("  ✓ Magisk in Memory\n");
                if (magiskProcess) sb.append("  ✓ Magisk Process\n");
                if (magiskSockets) sb.append("  ✓ Magisk Sockets\n");
                if (zygisk) sb.append("  ✓ Zygisk Detected\n");
                if (magiskMounts) sb.append("  ✓ Magisk Mounts\n");
                if (magiskTmpfs) sb.append("  ✓ Magisk Tmpfs\n");
                if (magiskOverlays) sb.append("  ✓ Magisk Overlays\n");
                if (suDaemonSocket) sb.append("  ✓ SU Daemon Socket\n");
                if (selinuxPermissive) sb.append("  ✓ SELinux Permissive\n");
                if (mountNamespace) sb.append("  ✓ Mount Namespace Manipulation\n");
                sb.append("\n");
            }

            if (countLowConfidenceIndicators() > 0) {
                sb.append("LOW CONFIDENCE INDICATORS (").append(countLowConfidenceIndicators()).append("):\n");
                if (testKeys) sb.append("  ✓ Test Keys\n");
                if (rootCloaking) sb.append("  ✓ Root Cloaking Apps\n");
                if (busybox) sb.append("  ✓ BusyBox\n");
                if (nativeHooks) sb.append("  ✓ Native Hooks\n");
                if (capabilities) sb.append("  ✓ Suspicious Capabilities\n");
                if (inotify) sb.append("  ✓ Inotify Watches\n");
                if (nativeBridge) sb.append("  ✓ Native Bridge\n");
                if (hiddenApps) sb.append("  ✓ Hidden Apps\n");
                if (suspiciousLatency) sb.append("  ✓ Suspicious Latency\n");
            }

            return sb.toString();
        }
    }
}