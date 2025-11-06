package com.webileapps.safeguard;

import android.content.Context;
import android.content.pm.ApplicationInfo;
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

        if (checkMagiskSuList()) detectionCount++;
        if (checkMagiskFileDescriptors()) detectionCount++;
        if (checkMagiskSocketConnections()) detectionCount++;
        if (checkMagiskInotify()) detectionCount++;
        if (checkMagiskTmpfs()) detectionCount++;
        if (checkMagiskOverlays()) detectionCount++;
        if (checkSuDaemonSocket()) detectionCount++;
      //  if (detectNativeLibraryHooks()) detectionCount++;
     //   if (checkMagiskHiddenApps()) detectionCount++;
        if (checkNativeBridgeInjection()) detectionCount++;
        if (checkSuspiciousLatency()) detectionCount++;


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

    private boolean checkMagiskSuList() {
        try {
            String[] suListPaths = {
                    "/data/adb/.magisk/config",
                    "/data/adb/magisk/magisk.db",
                    "/data/user_de/0/com.topjohnwu.magisk/databases/magisk.db",
                    "/data/adb/ksu/ksud",           // KernelSU
                    "/data/adb/ap/apsud"            // APatch
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
        } catch (Exception e) {
            // Access denied
        }
        return false;
    }

    /**
     * NEW CHECK 2: Check /proc/self/fd for Magisk file descriptors
     * File descriptors can reveal open Magisk files even when hidden
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
     * NEW CHECK 3: Check /proc/net/unix for Magisk socket connections
     * Magisk uses Unix domain sockets for IPC
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
                        Log.d(TAG, "Found Magisk socket: " + line);
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
     * NEW CHECK 4: Check for inotify watches (Magisk uses these)
     * Magisk monitors filesystem changes using inotify
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
     * NEW CHECK 5: Check for Magisk tmpfs mounts in mountinfo
     * More detailed than /proc/mounts
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
     * NEW CHECK 6: Check for Magisk overlay mounts
     * Magisk uses overlay filesystem to modify system
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

            // Check mountinfo for overlay filesystems
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
     * NEW CHECK 7: Check for su daemon socket
     * Magisk's su daemon creates socket files
     */
    private boolean checkSuDaemonSocket() {
        try {
            String[] socketPaths = {
                    "/dev/socket/magiskd",
                    "/dev/socket/su",
                    "/dev/.socket/magisk"
            };

            for (String path : socketPaths) {
                if (new File(path).exists()) {
                    Log.d(TAG, "Found su daemon socket: " + path);
                    return true;
                }
            }
        } catch (Exception e) {
            // Access denied
        }
        return false;
    }

    /**
     * NEW CHECK 8: Detect native library hooks
     * Magisk hooks native functions - check for evidence
     */
    private boolean detectNativeLibraryHooks() {
        try {
            return checkFunctionHook("open") ||
                    checkFunctionHook("stat") ||
                    checkFunctionHook("access");
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkFunctionHook(String functionName) {
        try {
            File mapsFile = new File("/proc/self/maps");
            BufferedReader reader = new BufferedReader(new FileReader(mapsFile));
            String line;

            while ((line = reader.readLine()) != null) {
                // Check for writable libc sections (indicates possible hooks)
                if (line.contains("libc.so") &&
                        (line.contains(" rw-") || line.contains(" rwx"))) {
                    reader.close();
                    Log.d(TAG, "Suspicious writable libc section detected");
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
     * NEW CHECK 9: Check for Magisk hiding apps from package manager
     * Compare package counts from different sources
     */
    private boolean checkMagiskHiddenApps() {
        try {
            PackageManager pm = context.getPackageManager();
            java.util.List<android.content.pm.PackageInfo> packages = pm.getInstalledPackages(0);
            int pmCount = packages.size();

            // Count apps in /data/app
            File dataApp = new File("/data/app");
            int fileCount = 0;
            if (dataApp.exists() && dataApp.isDirectory()) {
                File[] apps = dataApp.listFiles();
                if (apps != null) {
                    fileCount = apps.length;
                }
            }

            // Significant mismatch suggests hidden apps
            if (Math.abs(pmCount - fileCount) > 5) {
                Log.d(TAG, "Package count mismatch: PM=" + pmCount + ", Files=" + fileCount);
                return true;
            }
        } catch (Exception e) {
            // Access denied
        }
        return false;
    }

    /**
     * NEW CHECK 10: Check for Magisk's native bridge injection
     * Magisk can use native bridge for injection
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
     * NEW CHECK 11: Timing-based detection
     * Hooked functions add latency - detect abnormal delays
     */
    private boolean checkSuspiciousLatency() {
        try {
            long startTime = System.nanoTime();
            File file = new File("/system/bin/su");
            boolean exists = file.exists();
            long endTime = System.nanoTime();

            long duration = endTime - startTime;

            // Normal: < 1ms, Hooked: > 5ms
            if (duration > 5_000_000) { // 5ms in nanoseconds
                Log.d(TAG, "Suspicious latency detected: " + (duration / 1_000_000) + "ms");
                return true;
            }
        } catch (Exception e) {
            // Normal failure
        }
        return false;
    }

    /**
     * NEW CHECK 12: Enhanced package traits checking
     * Verify if suspicious packages have Magisk characteristics
     */
    private boolean checkPackageForMagiskTraits(String packageName) {
        try {
            PackageManager pm = context.getPackageManager();
            ApplicationInfo appInfo = pm.getApplicationInfo(packageName, 0);

            // Check app data directory for Magisk files
            String appDataPath = appInfo.dataDir;
            String[] magiskFiles = {
                    "databases/magisk.db",
                    "shared_prefs/config.xml",
                    "files/busybox"
            };

            for (String file : magiskFiles) {
                if (new File(appDataPath + "/" + file).exists()) {
                    Log.d(TAG, "Found Magisk trait in package: " + packageName);
                    return true;
                }
            }
        } catch (Exception e) {
            // Access denied
        }
        return false;
    }

    /**
     * BONUS: Check for Shamiko module (enhances Magisk hiding)
     */
    public boolean checkShamikoModule() {
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

    public DetectionReport getDetailedReport() {
        DetectionReport report = new DetectionReport();
        // Existing checks
        report.magiskApp = checkMagiskApp();
        report.magiskFiles = checkMagiskFiles();
        report.magiskDaemon = checkMagiskDaemon();
        report.magiskMount = checkMagiskMount();
        report.zygisk = checkZygisk();

        // New checks
        report.magiskSuList = checkMagiskSuList();
        report.fileDescriptors = checkMagiskFileDescriptors();
        report.socketConnections = checkMagiskSocketConnections();
        report.inotifyWatches = checkMagiskInotify();
        report.tmpfsMounts = checkMagiskTmpfs();
        report.overlayMounts = checkMagiskOverlays();
        report.suDaemonSocket = checkSuDaemonSocket();
       // report.nativeHooks = detectNativeLibraryHooks();
       // report.hiddenApps = checkMagiskHiddenApps();
        report.nativeBridge = checkNativeBridgeInjection();
        report.suspiciousLatency = checkSuspiciousLatency();
        report.shamiko = checkShamikoModule();

        report.totalIndicators = report.countIndicators();
        report.isDetected = report.totalIndicators >= 2;

        return report;
    }

    public static class DetectionReport {
        // Existing checks
        public boolean magiskApp = false;
        public boolean magiskFiles = false;
        public boolean magiskDaemon = false;
        public boolean magiskMount = false;
        public boolean zygisk = false;

        // New checks
        public boolean magiskSuList = false;
        public boolean fileDescriptors = false;
        public boolean socketConnections = false;
        public boolean inotifyWatches = false;
        public boolean tmpfsMounts = false;
        public boolean overlayMounts = false;
        public boolean suDaemonSocket = false;
        public boolean nativeHooks = false;
        public boolean hiddenApps = false;
        public boolean nativeBridge = false;
        public boolean suspiciousLatency = false;
        public boolean shamiko = false;

        public int totalIndicators = 0;
        public boolean isDetected = false;

        public int countIndicators() {
            int count = 0;
            if (magiskApp) count++;
            if (magiskFiles) count++;
            if (magiskDaemon) count++;
            if (magiskMount) count++;
            if (zygisk) count++;
            if (magiskSuList) count++;
            if (fileDescriptors) count++;
            if (socketConnections) count++;
            if (inotifyWatches) count++;
            if (tmpfsMounts) count++;
            if (overlayMounts) count++;
            if (suDaemonSocket) count++;
            if (nativeHooks) count++;
            if (hiddenApps) count++;
            if (nativeBridge) count++;
            if (suspiciousLatency) count++;
            if (shamiko) count++;
            return count;
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("Magisk Detection Report\n");
            sb.append("======================\n");
            sb.append("Total Indicators: ").append(totalIndicators).append("/17\n");
            sb.append("Detection Status: ").append(isDetected ? "ROOTED" : "CLEAN").append("\n\n");
            sb.append("Existing Checks:\n");
            sb.append("  - Magisk App: ").append(magiskApp).append("\n");
            sb.append("  - Magisk Files: ").append(magiskFiles).append("\n");
            sb.append("  - Magisk Daemon: ").append(magiskDaemon).append("\n");
            sb.append("  - Magisk Mount: ").append(magiskMount).append("\n");
            sb.append("  - Zygisk: ").append(zygisk).append("\n\n");
            sb.append("New Checks:\n");
            sb.append("  - SuList/Config: ").append(magiskSuList).append("\n");
            sb.append("  - File Descriptors: ").append(fileDescriptors).append("\n");
            sb.append("  - Socket Connections: ").append(socketConnections).append("\n");
            sb.append("  - Inotify Watches: ").append(inotifyWatches).append("\n");
            sb.append("  - Tmpfs Mounts: ").append(tmpfsMounts).append("\n");
            sb.append("  - Overlay Mounts: ").append(overlayMounts).append("\n");
            sb.append("  - Su Daemon Socket: ").append(suDaemonSocket).append("\n");
            sb.append("  - Native Hooks: ").append(nativeHooks).append("\n");
            sb.append("  - Hidden Apps: ").append(hiddenApps).append("\n");
            sb.append("  - Native Bridge: ").append(nativeBridge).append("\n");
            sb.append("  - Suspicious Latency: ").append(suspiciousLatency).append("\n");
            sb.append("  - Shamiko Module: ").append(shamiko).append("\n");
            return sb.toString();
        }
    }


}