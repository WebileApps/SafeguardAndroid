package com.webileapps.protect.sample

import android.app.Activity
import android.app.Application
import android.content.Context
import android.os.Process
import androidx.lifecycle.ProcessLifecycleOwner
import com.webileapps.safeguard.AppLifecycleObserver

class MyApplication : Application() {

    override fun onCreate() {
        super.onCreate()

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
