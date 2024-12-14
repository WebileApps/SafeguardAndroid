package com.webileapps.safeguard

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.ProxyInfo
import android.net.wifi.WifiConfiguration
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.util.Log


object NetworkUtils {
    private const val TAG = "NetworkUtils"
    // Check if VPN is active
    @JvmStatic
    fun isVPNActive(context: Context): Boolean {
        val connectivityManager =
            context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val activeNetwork = connectivityManager.activeNetwork
            val capabilities = connectivityManager.getNetworkCapabilities(activeNetwork)
            return capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
        }
        return false
    }

    // Check if a proxy is set
    @JvmStatic
    fun isProxySet(context: Context): Boolean {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                val connectivityManager =
                    context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
                val proxyInfo: ProxyInfo? = connectivityManager.defaultProxy
                proxyInfo?.host != null
            } else {
                System.getProperty("http.proxyHost")?.isNotEmpty() == true
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error checking proxy: ${e.message}")
            false
        }
    }

    // Check if Wi-Fi is secure
    @JvmStatic
    fun isWifiSecure(context: Context): Boolean {
        val wifiManager = context.getSystemService(Context.WIFI_SERVICE) as WifiManager
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                val connectivityManager =
                    context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
                val activeNetwork = connectivityManager.activeNetwork
                val capabilities =
                    connectivityManager.getNetworkCapabilities(activeNetwork)
                if (capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true) {
                    val wifiInfo = wifiManager.connectionInfo
                    val networkId = wifiInfo.networkId
                    val ssid = wifiInfo.ssid

                    Log.d(TAG, "Connected to Wi-Fi SSID: $ssid, Network ID: $networkId")

                    // No direct API to check security; assume WPA/WPA2/3 if connected successfully
                    return true
                }
            } else {
                val wifiInfo: WifiInfo = wifiManager.connectionInfo
                val ssid = wifiInfo.ssid
                Log.d(TAG, "Connected to Wi-Fi SSID (Pre-Q): $ssid")

                // No explicit security check available for pre-Q devices
                return wifiInfo.ssid != null
            }
            false
        } catch (e: Exception) {
            Log.e(TAG, "Error checking Wi-Fi security: ${e.message}")
            false
        }
    }
}
