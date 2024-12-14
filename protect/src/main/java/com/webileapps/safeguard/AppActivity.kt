package com.webileapps.safeguard

import android.content.Context
import android.os.Bundle
import android.view.MotionEvent
import android.view.WindowManager
import androidx.appcompat.app.AppCompatActivity


open class AppActivity : AppCompatActivity() {
    companion object{
        lateinit var context:Context
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        /*TODO: Tapjacking Prevention*/
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
        context = this


    }

    override fun dispatchTouchEvent(event: MotionEvent): Boolean {
        if ((event.flags and MotionEvent.FLAG_WINDOW_IS_OBSCURED) != 0) {
            // Alert user and block the touch event
            showToast(getString(R.string.tap_jacking_alert))
            return false // Block event processing
        }
        return super.dispatchTouchEvent(event) // Allow normal event processing
    }

}