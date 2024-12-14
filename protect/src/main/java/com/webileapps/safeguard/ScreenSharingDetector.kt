import android.content.Context
import android.media.MediaRouter
import android.util.Log
import android.hardware.display.DisplayManager
import android.view.Display

object ScreenSharingDetector {
    private const val TAG = "ScreenSharingDetector"

    fun isScreenSharingActive(context: Context): Boolean {
        val mediaRouter = context.getSystemService(Context.MEDIA_ROUTER_SERVICE) as MediaRouter
        val route = mediaRouter.getSelectedRoute(MediaRouter.ROUTE_TYPE_LIVE_VIDEO)

        val isScreenSharing = route != null && route.isEnabled && route.deviceType == MediaRouter.RouteInfo.DEVICE_TYPE_TV
        Log.d(TAG, "Screen Sharing Active: $isScreenSharing")
        return isScreenSharing
    }

    fun isScreenMirrored(context: Context): Boolean {
        val displayManager = context.getSystemService(Context.DISPLAY_SERVICE) as DisplayManager
        val displays = displayManager.displays

        for (display in displays) {
            if (display.displayId != Display.DEFAULT_DISPLAY) {
                Log.d("ScreenSharingDetector", "Screen Mirrored to: ${display.name}")
                return true
            }
        }
        return false
    }
}



