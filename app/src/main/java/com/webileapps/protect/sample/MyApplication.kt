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

        // Initialize network monitoring
        networkChangeReceiver = NetworkChangeReceiver()
        val filter = IntentFilter(ConnectivityManager.CONNECTIVITY_ACTION)
        registerReceiver(networkChangeReceiver, filter)

        // Add lifecycle observer
        ProcessLifecycleOwner.get().lifecycle.addObserver(
            AppLifecycleObserver(this)
        )
    }

    companion object {
        private var currentActivity: Activity? = null

        @JvmStatic
        fun getCurrentActivity(): Activity? = currentActivity

        @JvmStatic
        fun setCurrentActivity(activity: Activity?) {
            currentActivity = activity
        }
    }
}
