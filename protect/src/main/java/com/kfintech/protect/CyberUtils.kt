package com.kfintech.protect

import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import android.widget.Toast


fun AppLifecycleObserver.showToast(context: Context, message: String) {
    Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
}
fun Activity.showToast(message: String) {
    Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
}

fun getPackageName(context: Context):String{
    val applicationInfo = context.packageManager.getApplicationInfo(context.packageName,
        PackageManager.GET_META_DATA)
    return applicationInfo.metaData.getString("package_name","")
}