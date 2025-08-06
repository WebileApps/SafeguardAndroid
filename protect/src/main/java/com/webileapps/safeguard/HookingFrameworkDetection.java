package com.webileapps.safeguard;

import android.content.Context;
import android.content.pm.PackageManager;

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class HookingFrameworkDetection {
    public static boolean detectXposedClass() {
        try {
            Class.forName("de.robv.android.xposed.XposedHelpers");
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        }
    }

    public static boolean hasHookingAppsInstalled(Context context) {
        String[] knownHookApps = {
                "de.robv.android.xposed.installer",  // Xposed
                "com.saurik.substrate",              // Substrate
                "org.lsposed.manager",               // LSPosed
                "com.devadvance.rootcloak",          // Root hiding tool
                "re.frida.server"                    // Frida
        };

        for (String pkg : knownHookApps) {
            try {
                context.getPackageManager().getPackageInfo(pkg, 0);
                return true;
            } catch (PackageManager.NameNotFoundException e) {
                // not installed
            }
        }
        return false;
    }

    public static boolean isStackTraceHooked() {
        try {
            throw new Exception("Check stack trace");
        } catch (Exception e) {
            for (StackTraceElement element : e.getStackTrace()) {
                String trace = element.getClassName();
                if (trace.contains("frida") || trace.contains("xposed") || trace.contains("substrate")) {
                    return true;
                }
            }
        }
        return false;
    }
    public static boolean isHookLibLoaded() {
        String[] badLibs = {
                "libsubstrate.so", "libxposed.so", "libfrida-agent.so"
        };
        for (String lib : badLibs) {
            try {
                System.loadLibrary(lib);
                return true;
            } catch (UnsatisfiedLinkError ignored) {}
        }
        return false;
    }

    public static boolean detectFrida() {
        try {
            Class.forName("re.frida.server.FridaService");
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        }
    }

    public static boolean isFridaRunning() {
        try {
            Process process = Runtime.getRuntime().exec("ps");
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("frida") || line.contains("gum-js-loop")) {
                    return true;
                }
            }
        } catch (Exception ignored) {}
        return false;
    }

    public static boolean isHookingDetected(Context context) {
        return detectXposedClass()
                || detectFrida()
                || hasHookingAppsInstalled(context)
                || isFridaRunning()
                || isStackTraceHooked()
                || isHookLibLoaded();
    }

}
