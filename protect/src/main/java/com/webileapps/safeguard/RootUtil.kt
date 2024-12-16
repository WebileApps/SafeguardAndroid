package com.webileapps.safeguard

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader


class RootUtil(val context : Context) {
    val isDeviceRooted: Boolean
        get() =/* 1 TODO: REs shall explore the feasibility of implementing a code that checks if the device is rooted/ jailbroken prior to the installation of the mobile application and disallow the mobile application to install/ function if the phone is rooted/ jailbroken*/

            isRunningOnEmulator || checkRootMethod1() || checkRootMethod2() || checkRootMethod3() || checkRootMethod4() || checkRootMethod5() || checkRootMethod6() || rootClockingCheck()

    private fun checkRootMethod1(): Boolean {
        val buildTags = Build.TAGS
        return buildTags != null && buildTags.contains("test-keys")
    }

    private fun checkRootMethod2(): Boolean {
        val paths = arrayOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
            "/su/bin/su"
        )
        for (path in paths) {
            if (File(path).exists()) return true
        }
        return false
    }

    val isRunningOnEmulator: Boolean
        get() {
            val brand = Build.BRAND
            val device = Build.DEVICE
            val model = Build.MODEL
            val product = Build.PRODUCT

            return brand.startsWith("generic") || device.startsWith("generic") || model.contains("google_sdk") || product.contains(
                "sdk"
            )
        }

    private fun checkRootMethod3(): Boolean {
        var process: Process? = null
        try {
            process = Runtime.getRuntime().exec(arrayOf("/system/xbin/which", "su"))
            val `in` = BufferedReader(InputStreamReader(process.inputStream))
            if (`in`.readLine() != null) return true
            return false
        } catch (t: Throwable) {
            return false
        } finally {
            process?.destroy()
        }
    }

    private fun checkRootMethod4(): Boolean {
        val paths = arrayOf(
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su"
        )
        for (path in paths) {
            if (File(path).exists()) {
                return true
            }
        }
        return false
    }

    // Method 2: Try executing the "su" command
    private fun checkRootMethod5(): Boolean {
        var process: Process? = null
        try {
            process = Runtime.getRuntime().exec("su")
            val `in` = BufferedReader(InputStreamReader(process.inputStream))
            val output = `in`.readLine()
            if (output != null) {
                return true
            }
        } catch (e: Exception) {
            Log.e("RootCheck", "Not rooted or su command failed", e)
        } finally {
            process?.destroy()
        }
        return false
    }

    // Method 3: Look for common root files
    private fun checkRootMethod6(): Boolean {
        val paths = arrayOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
            "/system/app/SuperSU.apk",
            "/system/etc/init.d/99SuperSUDaemon"
        )
        for (path in paths) {
            if (File(path).exists()) {
                return true
            }
        }
        return false
    }

    fun  rootClockingCheck():Boolean{

        val packeges = arrayOf(
               "com.devadvance.rootcloak",
               "com.devadvance.rootcloakplus",
                "de.robv.android.xposed.installer",
                "com.saurik.substrate",
                "com.zachspong.temprootremovejb",
                "com.amphoras.hidemyroot",
                "com.amphoras.hidemyrootadfree",
                "com.formyhm.hiderootPremium",
                "com.formyhm.hideroot")

        val list = getAllInstalledApps()

        for(item in list){
            if(packeges.contains(item)){
                return true
            }
        }

        return false

    }

    private fun getAllInstalledApps(): List<String> {
        val packageManager: PackageManager = context.getPackageManager()
        val installedPackages = packageManager.getInstalledPackages(0)
        val packageNames: MutableList<String> = ArrayList()

        for (packageInfo in installedPackages) {
            if ((packageInfo.applicationInfo!!.flags and ApplicationInfo.FLAG_SYSTEM) == 0) {
                packageNames.add(packageInfo.packageName)
            }
        }

        return packageNames
    }
}
