package com.kfintech.protect

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import com.kfintech.protect.NetworkUtils.isProxySet
import com.kfintech.protect.NetworkUtils.isVPNActive
import com.kfintech.protect.NetworkUtils.isWifiSecure


class NetworkChangeReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        // Check network status
        if (isNetworkConnected(context)) {
            if (isVPNActive(context)) {
                // Handle VPN detection
                println("VPN is active")
            }
            if (isProxySet(context)) {
                // Handle proxy detection
                println("Proxy is enabled")
            }
            if (!isWifiSecure(context)) {
                // Handle unsecured Wi-Fi detection
                println("Connected to an unsecured Wi-Fi")
            }
        } else {
            println("No network connection")
        }
    }

    private fun isNetworkConnected(context: Context): Boolean {
        val connectivityManager =
            context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val activeNetwork = connectivityManager.activeNetworkInfo
        return activeNetwork != null && activeNetwork.isConnected
    }
}