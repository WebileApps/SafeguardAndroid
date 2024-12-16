package com.webileapps.protect.sample

import android.app.Activity
import android.app.Application
import android.content.IntentFilter
import android.net.ConnectivityManager
import androidx.lifecycle.ProcessLifecycleOwner
import com.webileapps.safeguard.AppLifecycleObserver
import com.webileapps.safeguard.NetworkChangeReceiver

class MyApplication : Application() {
    private var networkChangeReceiver: NetworkChangeReceiver? = null
    override fun onCreate() {
        super.onCreate()

        /*TODO: Mobile application shall check new network connections or connections for unsecured networks like VPN connection, proxy and unsecured Wi-Fi connections.77~@*/
        networkChangeReceiver = NetworkChangeReceiver()
        val filter = IntentFilter(ConnectivityManager.CONNECTIVITY_ACTION)
        registerReceiver(networkChangeReceiver, filter)

        ProcessLifecycleOwner.get().lifecycle.addObserver(
            AppLifecycleObserver(
                this
            )
        )
    }


    companion object {
        private var currentActivity: Activity? = null

        fun getCurrentActivity(): Activity? = currentActivity
    }
}
