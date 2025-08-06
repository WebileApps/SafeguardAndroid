package com.webileapps.safeguard;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Debug;
import android.util.Log;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

public class RootUtil {
    private final Context context;

    public RootUtil(Context context) {
        this.context = context;
    }

    public boolean isDeviceRooted() {
        return isRunningOnEmulator() || isDeviceTampered() || checkRootMethod2() || checkRootMethod3() ||
               checkRootMethod4() || checkRootMethod5() || checkRootMethod6() || rootClockingCheck()|| Debug.isDebuggerConnected()||isMagiskPresent();
    }


    private static boolean isDeviceTampered() {
        String buildTags = Build.TAGS;
        return buildTags != null && buildTags.contains("test-keys");
    }

    private boolean checkRootMethod2() {
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
            if (new File(path).exists()) return true;
        }
        return false;
    }

    public boolean isRunningOnEmulator() {
        String brand = Build.BRAND;
        String device = Build.DEVICE;
        String model = Build.MODEL;
        String product = Build.PRODUCT;

        return brand.startsWith("generic") || device.startsWith("generic") ||
               model.contains("google_sdk") || product.contains("sdk");
    }

    private boolean checkRootMethod3() {
        Process process = null;
        try {
            process = Runtime.getRuntime().exec(new String[]{"/system/xbin/which", "su"});
            BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
            return in.readLine() != null;
        } catch (Throwable t) {
            return false;
        } finally {
            if (process != null) {
                process.destroy();
            }
        }
    }

    private boolean checkRootMethod4() {
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
            if (new File(path).exists()) {
                return true;
            }
        }
        return false;
    }

    private boolean checkRootMethod5() {
        Process process = null;
        try {
            process = Runtime.getRuntime().exec(new String[]{"/system/xbin/which", "su"});
            BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String output = in.readLine();
            return output != null;
        } catch ( Exception e) {
            Log.e("RootCheck", "Not rooted or su command failed", e);
            return false;
        }finally {
            if (process != null) {
                process.destroy();
            }
        }
    }

    private boolean checkRootMethod6() {
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
            if (new File(path).exists()) {
                return true;
            }
        }
        return false;
    }

    public boolean rootClockingCheck() {
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
    }

    private List<String> getAllInstalledApps() {
        PackageManager packageManager = context.getPackageManager();

        // Query installed apps (ensure QUERY_ALL_PACKAGES is handled)
        List<android.content.pm.PackageInfo> installedPackages = packageManager.getInstalledPackages(PackageManager.GET_META_DATA);
        List<String> packageNames = new ArrayList<>();

        for (android.content.pm.PackageInfo packageInfo : installedPackages) {
            ApplicationInfo appInfo = packageInfo.applicationInfo;

            // Ensure it's a user-installed app
            if ((appInfo.flags & ApplicationInfo.FLAG_SYSTEM) == 0 ||
                    (appInfo.flags & ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0) {
                packageNames.add(appInfo.packageName);
            }
        }
        return packageNames;
    }

    public static boolean isMagiskPresent() {
        String[] paths = {
                "/sbin/magisk", "/data/adb/magisk", "/data/adb/modules"
        };
        for (String path : paths) {
            if (new File(path).exists()) return true;
        }
        return false;
    }

    public static boolean isBootloaderUnlocked() {
        try {
            Process process = Runtime.getRuntime().exec("getprop ro.boot.verifiedbootstate");
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String state = reader.readLine();
            reader.close();

            // Normally: "green" = locked, "orange"/"yellow"/"red" = unlocked or tampered
            return state != null && !"green".equalsIgnoreCase(state.trim());
        } catch (Exception e) {
            e.printStackTrace();
            return true; // Assume unsafe if check fails
        }
    }

    public static boolean isBootloaderInsecure() {
        String bootloader = Build.BOOTLOADER;
        return bootloader != null && bootloader.toLowerCase().contains("unlock");
    }

    public static boolean isFastbootEnabled() {
        return new File("/sys/class/android_usb/android0/f_fastboot").exists();
    }

    public static boolean isBootStateUntrusted() {
        return isBootloaderUnlocked() || isDeviceTampered() ||isBootloaderInsecure() || isFastbootEnabled();
    }




}
