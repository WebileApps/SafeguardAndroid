package com.webileapps.safeguard;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.UserManager;

import java.util.Arrays;
import java.util.List;

public class ParallelAppPrevention {

    private static final List<String> knownCloners = Arrays.asList(
            "com.lbe.parallel",        // Parallel Space
            "com.b32apps.appcloner",   // App Cloner
            "com.dualspace",           // Dual Space
            "com.rhmsoft.shelter",     // Shelter
            "com.oasisfeng.island"     // Island
    );

    public static boolean isAppCloned(Context context) {
        return !context.getPackageName().equals(context.getApplicationInfo().processName);
    }

    public static boolean isClonedByPath(Context context) {
        String path = context.getFilesDir().getAbsolutePath();
        return !path.startsWith("/data/user/0/") && !path.startsWith("/data/data/");
    }

    public static boolean detectCloneByFilePath(Context context) {
        return isClonedByPath(context);
    }

    public static boolean isClonerInstalled(Context context) {
        try {
            PackageManager pm = context.getPackageManager();
            List<ApplicationInfo> packages = pm.getInstalledApplications(0);
            for (ApplicationInfo app : packages) {
                if (knownCloners.contains(app.packageName)) {
                    return true;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    public static boolean detectMultipleUsers(Context context) {
        try {
            UserManager userManager = (UserManager) context.getSystemService(Context.USER_SERVICE);
            return userManager.getUserProfiles().size() > 1;
        } catch (Exception e) {
            return false;
        }
    }

    public static boolean isSecondSpaceAvailable(Context context) {
        return isAppCloned(context)
                || isClonedByPath(context)
                || isClonerInstalled(context)
                || detectMultipleUsers(context)
                || detectCloneByFilePath(context);
    }
}
