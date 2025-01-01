package com.webileapps.safeguard;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.util.Log;

/**
 * BroadcastReceiver to detect network changes.
 */
public class NetworkChangeReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        // Check network status
        if (isNetworkConnected(context)) {
            if (NetworkUtils.isVPNActive(context)) {
                SecurityConfigManager.getSecurityChecker().showSecurityDialog(
                    AppActivity.context, 
                    context.getString(R.string.vpn_warning), 
                    false, 
                    () -> {}
                );
            }
            else if (NetworkUtils.isProxySet(context)) {
                // Handle proxy detection
                SecurityConfigManager.getSecurityChecker().showSecurityDialog(
                    AppActivity.context, 
                    context.getString(R.string.proxy_warning), 
                    false, 
                    () -> {}
                );
            }
            else if (!NetworkUtils.isWifiSecure(context)) {
                // Handle unsecured Wi-Fi detection
                SecurityConfigManager.getSecurityChecker().showSecurityDialog(
                    AppActivity.context, 
                    context.getString(R.string.usecured_network_warning), 
                    false, 
                    () -> {}
                );
            }
        } else {
            Log.d("NetworkChangeReceiver", "No network connection");
        }
    }

    /**
     * Checks if the network is connected.
     *
     * @param context The application context.
     * @return True if the network is connected, false otherwise.
     */
    private boolean isNetworkConnected(Context context) {
        ConnectivityManager connectivityManager = 
            (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        NetworkInfo activeNetwork = connectivityManager.getActiveNetworkInfo();
        return activeNetwork != null && activeNetwork.isConnected();
    }
}
