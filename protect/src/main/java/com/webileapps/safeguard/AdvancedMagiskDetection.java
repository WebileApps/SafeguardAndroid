package com.webileapps.safeguard;

import android.content.Context;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class AdvancedMagiskDetection {

    private final Context context;

    public AdvancedMagiskDetection(Context context) {
        this.context = context;
    }

    /**
     * Main detection method - call this from isDeviceRooted()
     */
    public boolean detectMagiskWithDenyList() {
        return checkMagiskSuList() ||
                checkMagiskRandomPackages() ||
                checkMagiskFileDescriptors() ||
                checkMagiskMemoryMaps() ||
                checkZygiskDetection() ||
                checkMagiskSocketConnections() ||
                checkMagiskInotify() ||
                checkMagiskTmpfs() ||
                checkMagiskOverlays() ||
                checkSuDaemonSocket() ||
                detectNativeLibraryHooks() ||
                checkMagiskHiddenApps();
    }

    /**
     * Check for Magisk's sulist - even with DenyList enabled
     */
    private boolean checkMagiskSuList() {
        try {
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
                        return true;
                    }
                } catch (Exception ignored) {
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Detect Magisk hidden as random package names
     */
    private boolean checkMagiskRandomPackages() {
        try {
            // Magisk Manager often hides with random package names
            // Check for apps with suspicious characteristics
            String[] suspiciousPatterns = {
                    "^[a-z]\\.[a-z]$",           // Single letter: a.b, a.c
                    "^[a-z]{2}\\.[a-z]{2}$",     // Two letters: ab.cd
                    "^com\\.[a-z]{2,4}$",        // Short names: com.ab
                    "^io\\.github\\.[a-z]+\\.magisk$"
            };

            // Check installed apps for matching patterns
            android.content.pm.PackageManager pm = context.getPackageManager();
            java.util.List<android.content.pm.PackageInfo> packages = pm.getInstalledPackages(0);

            for (android.content.pm.PackageInfo pkg : packages) {
                String pkgName = pkg.packageName;
                for (String pattern : suspiciousPatterns) {
                    if (pkgName.matches(pattern)) {
                        // Check if app has Magisk-like permissions or files
                        if (checkPackageForMagiskTraits(pkgName)) {
                            return true;
                        }
                    }
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkPackageForMagiskTraits(String packageName) {
        try {
            // Check if package has superuser-like permissions
            android.content.pm.PackageManager pm = context.getPackageManager();
            android.content.pm.ApplicationInfo appInfo = pm.getApplicationInfo(packageName, 0);

            // Check app data directory for Magisk files
            String appDataPath = appInfo.dataDir;
            String[] magiskFiles = {"databases/magisk.db", "shared_prefs/config.xml", "files/busybox"};

            for (String file : magiskFiles) {
                if (new File(appDataPath + "/" + file).exists()) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Check /proc/self/fd for Magisk file descriptors
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
                            return true;
                        }
                    } catch (Exception ignored) {
                    }
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Check /proc/self/maps for Magisk memory mappings
     */
    private boolean checkMagiskMemoryMaps() {
        try {
            BufferedReader reader = new BufferedReader(new FileReader("/proc/self/maps"));
            String line;

            Set<String> suspiciousPatterns = new HashSet<>(Arrays.asList(
                    "magisk", "libmagisk", "zygisk", "/sbin/",
                    "libsu.so", "libriru", "libxposed"
            ));

            while ((line = reader.readLine()) != null) {
                String lowerLine = line.toLowerCase();
                for (String pattern : suspiciousPatterns) {
                    if (lowerLine.contains(pattern)) {
                        reader.close();
                        return true;
                    }
                }
            }
            reader.close();
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Detect Zygisk (Magisk's Zygote injection)
     */
    private boolean checkZygiskDetection() {
        try {
            // Check for Zygisk library in process
            File mapsFile = new File("/proc/self/maps");
            if (mapsFile.exists()) {
                BufferedReader reader = new BufferedReader(new FileReader(mapsFile));
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.contains("zygisk") ||
                            line.contains("libzygisk") ||
                            line.contains("zygote-loader")) {
                        reader.close();
                        return true;
                    }
                }
                reader.close();
            }

            // Check for Zygisk environment variables
            String zygiskEnv = System.getenv("ZYGISK_ENABLED");
            if (zygiskEnv != null && zygiskEnv.equals("1")) {
                return true;
            }

            return false;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Check for Magisk socket connections
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
                        return true;
                    }
                }
                reader.close();
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Check for inotify watches (Magisk uses these)
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
                                return true;
                            }
                        }
                        reader.close();
                    }
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Check for Magisk tmpfs mounts
     */
    private boolean checkMagiskTmpfs() {
        try {
            BufferedReader reader = new BufferedReader(new FileReader("/proc/self/mountinfo"));
            String line;

            while ((line = reader.readLine()) != null) {
                // Magisk creates specific tmpfs mounts
                if (line.contains("tmpfs") &&
                        (line.contains("/sbin") ||
                                line.contains("magisk") ||
                                line.contains("/dev/magisk"))) {
                    reader.close();
                    return true;
                }
            }
            reader.close();
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Check for Magisk overlay mounts
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
                    return true;
                }
            }

            // Check mountinfo for overlay filesystems
            BufferedReader reader = new BufferedReader(new FileReader("/proc/self/mountinfo"));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("overlay") && line.contains("magisk")) {
                    reader.close();
                    return true;
                }
            }
            reader.close();
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Check for su daemon socket
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
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Detect native library hooks
     */
    private boolean detectNativeLibraryHooks() {
        try {
            // Check if common functions are hooked
            return checkFunctionHook("open") ||
                    checkFunctionHook("stat") ||
                    checkFunctionHook("access") ||
                    checkFunctionHook("readlink");
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkFunctionHook(String functionName) {
        try {
            // Load libc and check if function pointer is in expected range
            System.loadLibrary("c");

            // This is a simplified check - in production, use native code
            // to check actual function addresses against expected values
            File mapsFile = new File("/proc/self/maps");
            BufferedReader reader = new BufferedReader(new FileReader(mapsFile));
            String line;

            boolean foundSuspicious = false;
            while ((line = reader.readLine()) != null) {
                if (line.contains("libc.so") &&
                        (line.contains("rw") || line.contains("rwx"))) {
                    // Writable libc sections indicate possible hooks
                    foundSuspicious = true;
                    break;
                }
            }
            reader.close();
            return foundSuspicious;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Check for Magisk hiding apps from package manager
     */
    private boolean checkMagiskHiddenApps() {
        try {
            // Compare package list from different sources
            android.content.pm.PackageManager pm = context.getPackageManager();
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
            return Math.abs(pmCount - fileCount) > 5;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Check for Magisk's native bridge injection
     */
    private boolean checkNativeBridgeInjection() {
        try {
            String nativeBridge = System.getProperty("ro.dalvik.vm.native.bridge");
            if (nativeBridge != null && !nativeBridge.isEmpty() &&
                    !nativeBridge.equals("0")) {
                return true;
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Timing-based detection - Magisk hooks add latency
     */
    private boolean checkSuspiciousLatency() {
        try {
            long startTime = System.nanoTime();
            File file = new File("/system/bin/su");
            boolean exists = file.exists();
            long endTime = System.nanoTime();

            long duration = endTime - startTime;

            // If file.exists() takes too long, it might be hooked
            // Normal operation: < 1ms, Hooked: > 5ms
            return duration > 5_000_000; // 5ms in nanoseconds
        } catch (Exception e) {
            return false;
        }
    }
}