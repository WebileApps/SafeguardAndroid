package com.webileapps.safeguard;

import android.Manifest;
import android.content.Context;
import android.content.pm.PackageManager;
import android.location.Location;
import android.location.LocationManager;
import androidx.core.app.ActivityCompat;
import java.util.List;

public class MockLocationDetection {
    // Check if Mock Location is enabled
    public static boolean isMockLocationEnabled(Context context) {
        try {
            LocationManager locationManager = 
                (LocationManager) context.getSystemService(Context.LOCATION_SERVICE);
            List<String> providers = locationManager.getAllProviders();
            
            for (String provider : providers) {
                if (ActivityCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION) 
                        != PackageManager.PERMISSION_GRANTED 
                    && ActivityCompat.checkSelfPermission(context, Manifest.permission.ACCESS_COARSE_LOCATION) 
                        != PackageManager.PERMISSION_GRANTED) {
                    
                    Location location = locationManager.getLastKnownLocation(provider);
                    if (location != null && location.isFromMockProvider()) {
                        return true;
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }
}
