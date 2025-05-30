package com.webileapps.safeguard;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkCapabilities;
import android.net.ProxyInfo;
import android.net.wifi.WifiManager;
import android.util.Log;

public class NetworkUtils {
    private static final String TAG = "NetworkUtils";

    public static boolean isVPNActive(Context context) {
        ConnectivityManager connectivityManager = 
            (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        android.net.Network activeNetwork = connectivityManager.getActiveNetwork();
        NetworkCapabilities capabilities = connectivityManager.getNetworkCapabilities(activeNetwork);
        return capabilities != null && capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
    }
    public static boolean isProxySet(Context context) {
        try {
            ConnectivityManager connectivityManager = 
                (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
            ProxyInfo proxyInfo = connectivityManager.getDefaultProxy();
            return proxyInfo != null && proxyInfo.getHost() != null;
        } catch (Exception e) {
            Log.e(TAG, "Error checking proxy: " + e.getMessage());
            return false;
        }
    }
    public static boolean isWifiSecure(Context context) {
        WifiManager wifiManager = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
        try {
            ConnectivityManager connectivityManager = 
                (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
            android.net.Network activeNetwork = connectivityManager.getActiveNetwork();
            NetworkCapabilities capabilities = connectivityManager.getNetworkCapabilities(activeNetwork);

            if (capabilities != null && capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                android.net.wifi.WifiInfo wifiInfo = wifiManager.getConnectionInfo();
                String ssid = wifiInfo.getSSID();

                Log.d(TAG, "Connected to Wi-Fi SSID: " + ssid);
                return ssid != null && !ssid.isEmpty();
            } else if (capabilities != null && capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
                return true;
            }

            return false;
        } catch (Exception e) {
            Log.e(TAG, "Error checking Wi-Fi security: " + e.getMessage());
            return false;
        }
    }
}
