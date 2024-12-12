package com.kfintech.protect.sample

import android.app.Activity
import android.app.Application
import androidx.lifecycle.ProcessLifecycleOwner
import com.kfintech.protect.AppLifecycleObserver

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
