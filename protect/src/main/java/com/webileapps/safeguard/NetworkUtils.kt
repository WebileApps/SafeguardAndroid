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
        val activeNetwork = connectivityManager.activeNetwork
        val capabilities = connectivityManager.getNetworkCapabilities(activeNetwork)
        return capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true

    }

    // Check if a proxy is set
    @JvmStatic
    fun isProxySet(context: Context): Boolean {
        return try {
            val connectivityManager =
                context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val proxyInfo: ProxyInfo? = connectivityManager.defaultProxy
            proxyInfo?.host != null
        } catch (e: Exception) {
            Log.e(TAG, "Error checking proxy: ${e.message}")
            false
        }
    }

    @JvmStatic
    fun isWifiSecure(context: Context): Boolean {
        val wifiManager = context.getSystemService(Context.WIFI_SERVICE) as WifiManager
        return try {
            // For Android Q (API 29) and above
                val connectivityManager =
                    context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
                val activeNetwork = connectivityManager.activeNetwork
                val capabilities =
                    connectivityManager.getNetworkCapabilities(activeNetwork)


                if (capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true) {
                    // Connected to Wi-Fi, now check Wi-Fi security
                    val wifiInfo = wifiManager.connectionInfo
                    val ssid = wifiInfo.ssid

                    Log.d(TAG, "Connected to Wi-Fi SSID: $ssid")

                    // Since we cannot directly fetch Wi-Fi security type in Q+, assume secure if connected
                    return !ssid.isNullOrEmpty()
                }else if(capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true) {
                 return true
                    }

            // Return false if no valid Wi-Fi is detected
            false
        } catch (e: Exception) {
            Log.e(TAG, "Error checking Wi-Fi security: ${e.message}")
            false
        }
    }
}
