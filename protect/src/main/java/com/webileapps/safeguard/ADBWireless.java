package com.webileapps.safeguard;

import android.content.Context;
import android.provider.Settings;

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class ADBWireless {
    public static boolean isAdbEnabled(Context context) {
        try {
            int adb = Settings.Global.getInt(context.getContentResolver(), Settings.Global.ADB_ENABLED);
            return adb == 1;
        } catch (Settings.SettingNotFoundException e) {
            return false;
        }
    }

    public static boolean isAdbOverWiFi() {
        try {
            Process process = Runtime.getRuntime().exec("getprop service.adb.tcp.port");
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String port = reader.readLine();
            return port != null && !port.isEmpty() && !port.equals("-1");
        } catch (Exception e) {
            return false;
        }
    }

    public static boolean adbWirelessCheck(Context context){
        return isAdbEnabled(context) || isAdbOverWiFi();
    }

   /* if (isAdbEnabled(context) || isAdbOverWiFi()) {
        // Show warning
        new AlertDialog.Builder(context)
                .setTitle("Security Risk")
                .setMessage("ADB debugging is enabled. Please disable it to use this app.")
                .setPositiveButton("Exit", (dialog, which) -> {
                    System.exit(0);
                }).setCancelable(false)
                .show();
    }*/

}
