package com.webileapps.safeguard;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;

public class NetworkMonitor {
    private final Context context;
    private final ConnectivityManager connectivityManager;
    private NetworkChangeCallback networkCallback;

    public NetworkMonitor(Context context) {
        this.context = context;
        this.connectivityManager = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
    }

    public void startMonitoring(NetworkChangeCallback.NetworkChangeListener onNetworkChange) {
        networkCallback = new NetworkChangeCallback(onNetworkChange);
        NetworkRequest networkRequest = new NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .build();
        connectivityManager.registerNetworkCallback(networkRequest, networkCallback);
    }

    public void stopMonitoring() {
        if (networkCallback != null) {
            connectivityManager.unregisterNetworkCallback(networkCallback);
        }
    }
}
