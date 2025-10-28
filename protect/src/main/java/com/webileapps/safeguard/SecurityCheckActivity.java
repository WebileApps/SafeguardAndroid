package com.webileapps.safeguard;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.widget.Toast;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class SecurityCheckActivity {
    private static final String TAG = "SecurityCheck";
    private final Context context;
    private final ExecutorService executorService;
    private final Handler mainHandler;

    public SecurityCheckActivity(Context context) {
        this.context = context;
        this.executorService = Executors.newSingleThreadExecutor();
        this.mainHandler = new Handler(Looper.getMainLooper());
    }

    /**
     * Perform security check asynchronously using modern ExecutorService
     */
    public void performSecurityCheck() {
        executorService.execute(() -> {
            // Background thread
            RootCheckResult result = performRootCheck();

            // Post result to main thread
            mainHandler.post(() -> handleRootCheckResult(result));
        });
    }

    /**
     * Perform security check with callback
     */
    public void performSecurityCheck(SecurityCheckCallback callback) {
        executorService.execute(() -> {
            RootCheckResult result = performRootCheck();

            mainHandler.post(() -> {
                if (callback != null) {
                    callback.onCheckComplete(result);
                }
                handleRootCheckResult(result);
            });
        });
    }

    /**
     * Perform the actual root check (runs on background thread)
     */
    private RootCheckResult performRootCheck() {
        RootCheckResult result = new RootCheckResult();

        try {
            AdvancedRootDetection rootDetection = new AdvancedRootDetection(context);
            FocusedMagiskDetection magiskDetection = new FocusedMagiskDetection(context);

            // Check root
            result.isRooted = rootDetection.isDeviceRooted();
            result.isMagiskPresent = magiskDetection.isMagiskPresent();
            result.isEmulator = rootDetection.isEmulator();

            // Get detailed report
            result.report = rootDetection.getDetectionReport();

            Log.d(TAG, "Root check complete: " + result.toString());

        } catch (Exception e) {
            Log.e(TAG, "Error during root check", e);
            result.checkFailed = true;
        }

        return result;
    }

    /**
     * Handle the root check result (runs on main thread)
     */
    private void handleRootCheckResult(RootCheckResult result) {
        if (result.checkFailed) {
            Log.e(TAG, "Root check failed - allowing access");
            return;
        }

        Log.d(TAG, result.report);

        if (result.isEmulator) {
            handleEmulator();
        } else if (result.isRooted || result.isMagiskPresent) {
            handleRootedDevice();
        } else {
            handleSafeDevice();
        }
    }

    /**
     * Device is rooted - take action
     */
    private void handleRootedDevice() {
        Log.w(TAG, "Rooted device detected");

        Toast.makeText(context,
                "This device appears to be rooted. Some features may be restricted.",
                Toast.LENGTH_LONG).show();

      //  SecurityCheck.Critical(context.getString(R.string.rooted_critical));
    }

    /**
     * Running on emulator
     */
    private void handleEmulator() {
        Log.w(TAG, "Emulator detected");

        if (BuildConfig.DEBUG) {
            Log.d(TAG, "Emulator allowed in debug mode");
        } else {
            Toast.makeText(context,
                    "This app cannot run on emulators",
                    Toast.LENGTH_LONG).show();
        }
    }

    /**
     * Device passed security checks
     */
    private void handleSafeDevice() {
        Log.d(TAG, "Device passed security checks");
    }

    /**
     * Clean up resources when done
     */
    public void cleanup() {
        if (executorService != null && !executorService.isShutdown()) {
            executorService.shutdown();
        }
    }

    /**
     * Callback interface for async results
     */
    public interface SecurityCheckCallback {
        void onCheckComplete(RootCheckResult result);
    }

    /**
     * Result class to hold check results
     */
    public static class RootCheckResult {
        public boolean isRooted = false;
        public boolean isMagiskPresent = false;
        public boolean isEmulator = false;
        public boolean checkFailed = false;
        public String report = "";

        public boolean isDeviceCompromised() {
            return isRooted || isMagiskPresent;
        }

        @Override
        public String toString() {
            return "RootCheckResult{" +
                    "rooted=" + isRooted +
                    ", magisk=" + isMagiskPresent +
                    ", emulator=" + isEmulator +
                    ", failed=" + checkFailed +
                    '}';
        }
    }
}
