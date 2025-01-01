package com.webileapps.safeguard;

import android.content.Context;
import android.os.Bundle;
import android.view.MotionEvent;
import android.view.WindowManager;
import androidx.appcompat.app.AppCompatActivity;
import android.widget.Toast;

public class AppActivity extends AppCompatActivity {
    private static Context context;

    public static Context getContext() {
        return context;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // Tapjacking Prevention
        getWindow().setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        );
        context = this;
    }

    @Override
    public boolean dispatchTouchEvent(MotionEvent event) {
        if ((event.getFlags() & MotionEvent.FLAG_WINDOW_IS_OBSCURED) != 0) {
            // Alert user and block the touch event
            Toast.makeText(this, getString(R.string.tap_jacking_alert), Toast.LENGTH_SHORT).show();
            return false; // Block event processing
        }
        return super.dispatchTouchEvent(event); // Allow normal event processing
    }
}
