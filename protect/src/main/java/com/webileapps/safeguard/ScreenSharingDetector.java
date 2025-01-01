package com.webileapps.safeguard;

import android.content.Context;
import android.media.MediaRouter;
import android.util.Log;
import android.hardware.display.DisplayManager;
import android.view.Display;

public class ScreenSharingDetector {
    private static final String TAG = "ScreenSharingDetector";

    public static boolean isScreenSharingActive(Context context) {
        MediaRouter mediaRouter = (MediaRouter) context.getSystemService(Context.MEDIA_ROUTER_SERVICE);
        MediaRouter.RouteInfo route = mediaRouter.getSelectedRoute(MediaRouter.ROUTE_TYPE_LIVE_VIDEO);

        boolean isScreenSharing = route != null && route.isEnabled() && 
                                route.getDeviceType() == MediaRouter.RouteInfo.DEVICE_TYPE_TV;
        Log.d(TAG, "Screen Sharing Active: " + isScreenSharing);
        return isScreenSharing;
    }

    public static boolean isScreenMirrored(Context context) {
        DisplayManager displayManager = (DisplayManager) context.getSystemService(Context.DISPLAY_SERVICE);
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
