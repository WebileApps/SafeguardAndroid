package com.webileapps.safeguard

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.util.Log
import com.webileapps.safeguard.NetworkUtils.isProxySet
import com.webileapps.safeguard.NetworkUtils.isVPNActive
import com.webileapps.safeguard.NetworkUtils.isWifiSecure

/**
 * BroadcastReceiver to detect network changes.
 */
class NetworkChangeReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {


        // Check network status
        if (isNetworkConnected(context)) {

           if (isVPNActive(context)) {
               SecurityConfigManager.getSecurityChecker().showSecurityDialog(AppActivity.context, context.getString(R.string.vpn_warning), false) {

               }
            }
            else if (isProxySet(context)) {
                // Handle proxy detection
               SecurityConfigManager.getSecurityChecker().showSecurityDialog(AppActivity.context, context.getString(R.string.proxy_warning), false) {

               }
            }
           else if (!isWifiSecure(context)) {
                // Handle unsecured Wi-Fi detection
               SecurityConfigManager.getSecurityChecker().showSecurityDialog(AppActivity.context, context.getString(R.string.usecured_network_warning), false) {

               }
            }
        } else {
            Log.d("NetworkChangeReceiver", "No network connection")
        }
    }

    /**
     * Checks if the network is connected.
     *
     * @param context The application context.
     * @return True if the network is connected, false otherwise.
     */
    private fun isNetworkConnected(context: Context): Boolean {
        val connectivityManager =
            context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val activeNetwork = connectivityManager.activeNetworkInfo
        return activeNetwork != null && activeNetwork.isConnected
    }
}