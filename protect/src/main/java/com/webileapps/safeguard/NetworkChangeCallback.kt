package com.webileapps.safeguard

import android.net.ConnectivityManager
import android.net.Network

class NetworkChangeCallback(private val onNetworkChange: (Boolean) -> Unit) : ConnectivityManager.NetworkCallback() {

    override fun onAvailable(network: Network) {
        super.onAvailable(network)
        // Network is available
        onNetworkChange(true)
    }

    override fun onLost(network: Network) {
        super.onLost(network)
        // Network is lost
        onNetworkChange(false)
    }
}