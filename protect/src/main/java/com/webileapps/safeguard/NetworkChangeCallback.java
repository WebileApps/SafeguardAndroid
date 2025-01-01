package com.webileapps.safeguard;

import android.net.ConnectivityManager;
import android.net.Network;

public class NetworkChangeCallback extends ConnectivityManager.NetworkCallback {
    private final NetworkChangeListener onNetworkChange;

    public interface NetworkChangeListener {
        void onNetworkChanged(boolean isAvailable);
    }

    public NetworkChangeCallback(NetworkChangeListener listener) {
        this.onNetworkChange = listener;
    }

    @Override
    public void onAvailable(Network network) {
        super.onAvailable(network);
        // Network is available
        onNetworkChange.onNetworkChanged(true);
    }

    @Override
    public void onLost(Network network) {
        super.onLost(network);
        // Network is lost
        onNetworkChange.onNetworkChanged(false);
    }
}
