package com.webileapps.safeguard;

import android.content.Context;
import android.media.MediaRouter;
import android.os.Build;
import android.util.Log;
import android.hardware.display.DisplayManager;
import android.view.Display;

public class ScreenSharingDetector {
    private static final String TAG = "ScreenSharingDetector";

    public static boolean isScreenSharingActive(Context context) {
        MediaRouter mediaRouter = (MediaRouter) context.getSystemService(Context.MEDIA_ROUTER_SERVICE);
        MediaRouter.RouteInfo route = mediaRouter.getSelectedRoute(MediaRouter.ROUTE_TYPE_LIVE_VIDEO);

        boolean isScreenSharing = false;

        if (route != null && route.isEnabled()) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                // Only call getDeviceType() on API 24 and above
                isScreenSharing = route.getDeviceType() == MediaRouter.RouteInfo.DEVICE_TYPE_TV;
            } else {
                // Fallback logic if needed for lower APIs — or assume no screen sharing
                Log.w(TAG, "getDeviceType() not supported on API < 24");
            }
        }

        Log.d(TAG, "Screen Sharing Active: " + isScreenSharing);
        return isScreenSharing;

    }

    public static boolean isScreenMirrored(Context context) {
        DisplayManager displayManager = (DisplayManager) context.getSystemService(Context.DISPLAY_SERVICE);
        if (displayManager == null) {
            Log.w(TAG, "DisplayManager not available. Cannot check for screen mirroring.");
            return false;
        }
        Display[] displays = displayManager.getDisplays();

        for (Display display : displays) {
            if (display.getDisplayId() != Display.DEFAULT_DISPLAY) {
                Log.d(TAG, "Screen Mirrored to: " + display.getName());
                return true;
            }
        }
        return false;
    }
}
