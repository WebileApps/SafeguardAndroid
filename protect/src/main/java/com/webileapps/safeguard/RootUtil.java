package com.webileapps.safeguard;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Debug;
import android.util.Log;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class RootUtil {
    private final Context context;

    public RootUtil(Context context) {
        this.context = context;
    }

    public boolean isDeviceRooted() {
        try {
                return isRunningOnEmulator() ||
                    isDeviceTampered() ||
                    checkRootMethod2() ||
                    checkRootMethod3() ||
                    checkRootMethod4() ||
                    checkRootMethod5() ||
                    checkRootMethod6() ||
                    rootClockingCheck() ||
                    Debug.isDebuggerConnected() ||
                    isMagiskPresent() ||
                    checkAdvancedMagiskDetection() ||
                    checkKernelModules() ||
                  //  checkMountPoints() ||
                        checkSuspiciousMounts()||
                    checkSystemProperties() ||
                    checkProcessList() ||
                    checkLibraryHooks() ||
                    checkSeLinuxStatus() ||
                    checkBusyBox() ||
                    checkXposedFramework();
        }catch (Exception e){
            return true;
        }
    }


    private boolean checkAdvancedMagiskDetection() {
        try {
            return checkMagiskDaemon() ||
                    checkMagiskMount() ||
                    checkMagiskProps() ||
                    checkMagiskManager() ||
                    checkMagiskBinary() ||
                    checkMagiskModules() ||
                    checkMagiskDatabase() ||
                    checkMagiskEnvironment();
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkMagiskDaemon() {
        try {
            // Check for Magisk daemon processes
            String[] processes = {"magiskd", "magiskinit", "magiskpolicy"};
            return checkRunningProcesses(processes);
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkMagiskMount() {
        try {
            // Check mount points that Magisk typically uses
            String[] mountPoints = {
                    "/dev/magisk",
                    "/sbin/.magisk",
                    "/cache/.magisk",
                    "/metadata/.magisk",
                    "/persist/.magisk",
                    "/mnt/vendor/persist/.magisk"
            };

            for (String mount : mountPoints) {
                if (new File(mount).exists()) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkMagiskProps() {
        try {
            // Check for Magisk-related system properties
            String[] props = {
                    "ro.magisk.version",
                    "ro.magisk.versioncode",
                    "init.svc.magiskd",
                    "ro.build.selinux"
            };

            for (String prop : props) {
                String value = getSystemProperty(prop);
                if (value != null && !value.isEmpty()) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkMagiskManager() {
        try {
            // Check for various Magisk Manager package names
            String[] magiskPackages = {
                    "com.topjohnwu.magisk",
                    "io.github.huskydg.magisk",
                    "com.magisk.manager",
                    "a.o", "a.b", "a.c", "a.d", "a.e", // Common random names
                    "io.github.vvb2060.magisk"
            };

            PackageManager pm = context.getPackageManager();
            for (String pkg : magiskPackages) {
                try {
                    pm.getPackageInfo(pkg, 0);
                    return true;
                } catch (PackageManager.NameNotFoundException e) {
                    // Continue checking
                }
            }

            // Check for suspicious single-letter package names
            return checkSuspiciousPackageNames();
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkSuspiciousPackageNames() {
        try {
            PackageManager pm = context.getPackageManager();
            List<android.content.pm.PackageInfo> packages = pm.getInstalledPackages(0);

            for (android.content.pm.PackageInfo pkg : packages) {
                String name = pkg.packageName;
                // Check for single letter package names (common Magisk hiding technique)
                if (name.matches("^[a-z]\\.[a-z]$")) {
                    try {
                        ApplicationInfo appInfo = pm.getApplicationInfo(name, 0);
                        // Check if it has suspicious permissions
                        if (hasSuspiciousPermissions(name)) {
                            return true;
                        }
                    } catch (Exception e) {
                        // Continue
                    }
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean hasSuspiciousPermissions(String packageName) {
        try {
            PackageManager pm = context.getPackageManager();
            String[] suspiciousPerms = {
                    "android.permission.ACCESS_SUPERUSER",
                    "android.permission.MOUNT_UNMOUNT_FILESYSTEMS",
                    "android.permission.WRITE_SECURE_SETTINGS"
            };

            for (String perm : suspiciousPerms) {
                if (pm.checkPermission(perm, packageName) == PackageManager.PERMISSION_GRANTED) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkMagiskBinary() {
        try {
            // Check for Magisk binaries in various locations
            String[] binaryPaths = {
                    "/sbin/magisk",
                    "/system/bin/magisk",
                    "/system/xbin/magisk",
                    "/vendor/bin/magisk",
                    "/data/adb/magisk/magisk32",
                    "/data/adb/magisk/magisk64",
                    "/cache/magisk",
                    "/dev/magisk/magisk"
            };

            for (String path : binaryPaths) {
                if (new File(path).exists()) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkMagiskModules() {
        try {
            String[] modulePaths = {
                    "/data/adb/modules",
                    "/sbin/.magisk/modules",
                    "/cache/.magisk/modules"
            };

            for (String path : modulePaths) {
                File moduleDir = new File(path);
                if (moduleDir.exists() && moduleDir.isDirectory()) {
                    String[] modules = moduleDir.list();
                    if (modules != null && modules.length > 0) {
                        return true;
                    }
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkMagiskDatabase() {
        try {
            String[] dbPaths = {
                    "/data/adb/magisk.db",
                    "/data/user_de/0/com.topjohnwu.magisk/databases",
                    "/cache/magisk.db"
            };

            for (String path : dbPaths) {
                if (new File(path).exists()) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkMagiskEnvironment() {
        try {
            // Check environment variables that Magisk might set
            Map<String, String> env = System.getenv();
            for (Map.Entry<String, String> entry : env.entrySet()) {
                String key = entry.getKey().toLowerCase();
                String value = entry.getValue().toLowerCase();
                if (key.contains("magisk") || value.contains("magisk")) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkKernelModules() {
        try {
            // Check for loaded kernel modules that might indicate root
            File procModules = new File("/proc/modules");
            if (procModules.exists()) {
                BufferedReader reader = new BufferedReader(new FileReader(procModules));
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.toLowerCase().contains("magisk") ||
                            line.toLowerCase().contains("superuser") ||
                            line.toLowerCase().contains("rootcloak")) {
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

  /*  private boolean checkMountPoints() {
        try {
            // Check /proc/mounts for suspicious mount points
            File procMounts = new File("/proc/mounts");
            if (procMounts.exists()) {
                BufferedReader reader = new BufferedReader(new FileReader(procMounts));
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.contains("magisk") ||
                            line.contains("/sbin") ||
                            line.contains("tmpfs /sbin") ||
                            line.contains("rootfs")) {
                        // Check if it's a suspicious mount
                        if (isSuspiciousMount(line)) {
                            reader.close();
                            Toast.makeText(context,"Check Mount Points",Toast.LENGTH_LONG).show();
                            return true;
                        }
                    }
                }
                reader.close();
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }*/

    private boolean checkSuspiciousMounts() {
        try (BufferedReader reader = new BufferedReader(new FileReader("/proc/mounts"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("magisk")) { // <-- only strong evidence
                    return true;
                }
            }
        } catch (Exception ignored) {}
        return false;
    }
    private boolean checkMountPoints() {
        try {
            File procMounts = new File("/proc/mounts");
            if (procMounts.exists()) {
                BufferedReader reader = new BufferedReader(new FileReader(procMounts));
                String line;
                while ((line = reader.readLine()) != null) {
                    // Only flag strong root indicators
                    if (line.contains("magisk") || line.contains("su") || line.contains("/magisk")) {
                        reader.close();
                        Toast.makeText(context, "Check Mount Points", Toast.LENGTH_LONG).show();
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

    private boolean isSuspiciousMount(String line) {
        // Ignore normal Android mounts
        if (line.startsWith("rootfs") && line.contains("rootfs / rootfs")) {
            return false;
        }
        if (line.contains("tmpfs /sbin") && !line.contains("magisk")) {
            return false;
        }
        // Anything else you consider bad
        return true;
    }


  /*  private boolean isSuspiciousMount(String mountLine) {
        // Analyze mount line for suspicious patterns
        return mountLine.contains("tmpfs /sbin") ||
                mountLine.contains("magisk") ||
                (mountLine.contains("/sbin") && mountLine.contains("rw"));
    }*/

    private boolean checkSystemProperties() {
        try {
            String[] suspiciousProps = {
                    "ro.debuggable",
                    "ro.secure",
                    "ro.build.type",
                    "ro.build.tags",
                    "ro.boot.veritymode",
                    "ro.boot.flash.locked",
                    "ro.boot.verifiedbootstate"
            };

            Map<String, String> expectedValues = new HashMap<>();
            expectedValues.put("ro.debuggable", "0");
            expectedValues.put("ro.secure", "1");
            expectedValues.put("ro.build.type", "user");
            expectedValues.put("ro.build.tags", "release-keys");

            for (String prop : suspiciousProps) {
                String value = getSystemProperty(prop);
                if (value != null) {
                    String expected = expectedValues.get(prop);
                    if (expected != null && !expected.equals(value)) {
                       return true;
                    }
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkProcessList() {
        try {
            String[] suspiciousProcesses = {
                    "magiskd", "magiskinit", "magisklogd", "magiskpolicy",
                    "su", "daemonsu", "superuser", "Superuser.apk"
            };

            return checkRunningProcesses(suspiciousProcesses);
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkRunningProcesses(String[] processNames) {
        try {
            Process process = Runtime.getRuntime().exec("ps");
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;

            while ((line = reader.readLine()) != null) {
                String lowerLine = line.toLowerCase();
                for (String procName : processNames) {
                    if (lowerLine.contains(procName.toLowerCase())) {
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

    private boolean checkLibraryHooks() {
        try {
            // Check for library hooking frameworks
            String[] libraries = {
                    "/system/lib/libriru_core.so",
                    "/system/lib64/libriru_core.so",
                    "/system/lib/libxposed_art.so",
                    "/system/lib64/libxposed_art.so"
            };

            for (String lib : libraries) {
                if (new File(lib).exists()) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkSeLinuxStatus() {
        try {
            String selinuxStatus = getSystemProperty("ro.boot.selinux");
            if ("permissive".equals(selinuxStatus)) {
                return true;
            }

            // Check if SELinux is enforcing but bypassed
            File selinuxEnforce = new File("/sys/fs/selinux/enforce");
            if (selinuxEnforce.exists()) {
                BufferedReader reader = new BufferedReader(new FileReader(selinuxEnforce));
                String enforce = reader.readLine();
                reader.close();
                if ("0".equals(enforce)) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkBusyBox() {
        try {
            String[] busyboxPaths = {
                    "/system/bin/busybox",
                    "/system/xbin/busybox",
                    "/sbin/busybox",
                    "/vendor/bin/busybox"
            };

            for (String path : busyboxPaths) {
                if (new File(path).exists()) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkXposedFramework() {
        try {
            // Check for Xposed Framework
            String[] xposedPaths = {
                    "/system/framework/XposedBridge.jar",
                    "/system/bin/app_process_xposed",
                    "/system/lib/libxposed_art.so"
            };

            for (String path : xposedPaths) {
                if (new File(path).exists()) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private String getSystemProperty(String key) {
        try {
            Process process = Runtime.getRuntime().exec("getprop " + key);
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
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

    private static boolean isDeviceTampered() {
        try {
            String buildTags = Build.TAGS;
            return buildTags != null && buildTags.contains("test-keys");

        } catch (Exception e) {
            return false;
        }
         }

    private boolean checkRootMethod2() {
        try {
            String[] paths = {
                    "/system/app/Superuser.apk",
                    "/sbin/su",
                    "/system/bin/su",
                    "/system/xbin/su",
                    "/data/local/xbin/su",
                    "/data/local/bin/su",
                    "/system/sd/xbin/su",
                    "/system/bin/failsafe/su",
                    "/data/local/su",
                    "/su/bin/su"
            };
            for (String path : paths) {
                try {
                    if (new File(path).exists()) {
                        return true;
                    }
                } catch (SecurityException ignored) {

                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    public boolean isRunningOnEmulator() {
        try {
            String brand = Build.BRAND;
            String device = Build.DEVICE;
            String model = Build.MODEL;
            String product = Build.PRODUCT;

            return (brand != null && brand.startsWith("generic")) ||
                    (device != null && device.startsWith("generic")) ||
                    (model != null && model.contains("google_sdk")) ||
                    (product != null && product.contains("sdk"));
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkRootMethod3() {
        Process process = null;
        BufferedReader in = null;
        try {

            if (!new File("/system/bin/which").exists() && !new File("/system/xbin/which").exists()) {
                return false;
            }
            process = Runtime.getRuntime().exec(new String[]{"/system/xbin/which", "su"});
             in = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String result = in.readLine();

            int exitCode = process.waitFor();

            return result != null && !result.trim().isEmpty();

        } catch (IOException e) {
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        } catch (Exception e) {
            return false;
        } finally {
            try {
                if (in != null) {
                    in.close();
                }
            } catch (IOException ignored) {
            }
            if (process != null) {
                try {
                    process.destroy();
                } catch (Exception ignored) {
                }
            }
        }
    }

    private boolean checkRootMethod4() {
        try {
            String[] paths = {
                    "/sbin/su",
                    "/system/bin/su",
                    "/system/xbin/su",
                    "/data/local/xbin/su",
                    "/data/local/bin/su",
                    "/system/sd/xbin/su",
                    "/system/bin/failsafe/su",
                    "/data/local/su"
            };
            for (String path : paths) {
                try {

                    if (new File(path).exists()) {
                        return true;
                    }
                } catch (SecurityException e) {

                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkRootMethod5() {
        Process process = null;
        BufferedReader reader = null;
        try {
            String[] whichPaths = {"/system/bin/which", "/system/xbin/which", "/bin/which", "/usr/bin/which"};
            String whichCommand = null;

            for (String path : whichPaths) {
                if (new File(path).exists()) {
                    whichCommand = path;
                    break;
                }
            }

            if (whichCommand == null) {
                 return false;
            }
            process = Runtime.getRuntime().exec(new String[]{whichCommand, "su"});
            reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String output = reader.readLine();
            // Wait for process to complete with timeout
            boolean finished;
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    finished = process.waitFor(3, java.util.concurrent.TimeUnit.SECONDS);
                }else{
                    int exitCode = process.waitFor();
                    finished = (exitCode == 0);
                }
            }catch (InterruptedException e){
                Thread.currentThread().interrupt();
                finished = false;
            }
            if (!finished) {
                process.destroyForcibly();
                return false;
            }
            return output != null && !output.trim().isEmpty();
        } catch (IOException e) {
            return false;
        }  catch (Exception e) {
            return false;
        } finally {
            try {
                if (reader != null) {
                    reader.close();
                }
            } catch (IOException ignored) {
            }
            if (process != null) {
                try {
                    process.destroy();
                } catch (Exception ignored) {
                }
            }
        }
    }

    private boolean checkRootMethod6() {
        try{
        String[] paths = {
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
            "/system/app/SuperSU.apk",
            "/system/etc/init.d/99SuperSUDaemon"
        };
        for (String path : paths) {
            try {

                if (new File(path).exists()) {
                    return true;
                }
            } catch (SecurityException ignored) {
            }}
            return false;
        }catch (Exception e){
            return false;
        }
    }

    public boolean rootClockingCheck() {
        try {
            String[] packages = {
                    "com.devadvance.rootcloak",
                    "com.devadvance.rootcloakplus",
                    "de.robv.android.xposed.installer",
                    "com.saurik.substrate",
                    "com.zachspong.temprootremovejb",
                    "com.amphoras.hidemyroot",
                    "com.amphoras.hidemyrootadfree",
                    "com.formyhm.hiderootPremium",
                    "com.formyhm.hideroot",
                    "com.noshufou.android.su",
                    "eu.chainfire.supersu",
                    "com.koushikdutta.superuser",
                    "com.thirdparty.superuser",
                    "com.zachspong.temprootremovejb",
                    "com.ramdroid.appquarantine"
            };

            List<String> installedApps = getAllInstalledApps();
            for (String packageName : packages) {
                if (installedApps.contains(packageName)) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private List<String> getAllInstalledApps() {
        List<String> packageNames = new ArrayList<>();
        try {
            PackageManager packageManager = context.getPackageManager();
            if (packageManager == null) {
                return packageNames;
            }

            List<android.content.pm.PackageInfo> installedPackages =
                    packageManager.getInstalledPackages(PackageManager.GET_META_DATA);

            for (android.content.pm.PackageInfo packageInfo : installedPackages) {
                try {
                    ApplicationInfo appInfo = packageInfo.applicationInfo;
                    if (appInfo != null) {
                        // Ensure it's a user-installed app
                        if ((appInfo.flags & ApplicationInfo.FLAG_SYSTEM) == 0 ||
                                (appInfo.flags & ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0) {
                            packageNames.add(appInfo.packageName);
                        }
                    }
                } catch (Exception ignored) {
                }
            }
        } catch (Exception ignored) {
        }
        return packageNames;
    }

    public static boolean isMagiskPresent() {
        try {
            String[] paths = {
                    "/sbin/magisk", "/data/adb/magisk", "/data/adb/modules"
            };
            for (String path : paths) {
                try {
                    if (new File(path).exists()) return true;
                }catch (SecurityException ignored){

                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    public static boolean isBootloaderUnlocked() {
        Process process = null;
        BufferedReader reader = null;
        try {
            process = Runtime.getRuntime().exec("getprop ro.boot.verifiedbootstate");
            reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String state = reader.readLine();

            boolean finished = process.waitFor(3, java.util.concurrent.TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                return true; // Assume unsafe if we can't check
            }

            // Normally: "green" = locked, "orange"/"yellow"/"red" = unlocked or tampered
            return state != null && !"green".equalsIgnoreCase(state.trim());
        } catch (IOException e) {
            return true; // Assume unsafe if check fails
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        } catch (Exception e) {
            return true; // Assume unsafe if check fails
        } finally {
            try {
                if (reader != null) {
                    reader.close();
                }
            } catch (IOException e) {
            }
            if (process != null) {
                try {
                    process.destroy();
                } catch (Exception e) {
                }
            }
        }
    }

    public static boolean isBootloaderInsecure() {
        try {
            String bootloader = Build.BOOTLOADER;
            return bootloader != null && bootloader.toLowerCase().contains("unlock");
        } catch (Exception e) {
            return false;
        }
    }

    public static boolean isFastbootEnabled() {
        try {
            return new File("/sys/class/android_usb/android0/f_fastboot").exists();
        } catch (SecurityException e) {
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    public static boolean isBootStateUntrusted() {
        try {
            boolean isBootloaderUnlocked = isBootloaderUnlocked();
            boolean isBootloaderInsecure = isBootloaderInsecure();
            boolean isFastbootEnabled = isFastbootEnabled();
            boolean isDeviceTampered = isDeviceTampered();
            return isBootloaderUnlocked() ||
                    isDeviceTampered() ||
                    isBootloaderInsecure() ||
                    isFastbootEnabled();
        } catch (Exception e) {
            return true; // Assume unsafe if we can't check
        }
    }
}
