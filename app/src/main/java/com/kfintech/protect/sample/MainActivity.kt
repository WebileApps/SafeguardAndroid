package com.kfintech.protect.sample

import android.content.IntentFilter
import android.net.ConnectivityManager
import android.os.Bundle
import android.util.Log
import android.widget.Toast
import com.kfintech.protect.AppActivity
import com.kfintech.protect.NetworkChangeReceiver
import com.kfintech.protect.SecurityChecker
import com.kfintech.protect.sample.databinding.ActivityMainBinding

class MainActivity : AppActivity() {
    private lateinit var binding: ActivityMainBinding
    private lateinit var securityChecker: SecurityChecker
    private lateinit var networkChangeReceiver: NetworkChangeReceiver

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)


        /*TODO: Mobile application shall check new network connections or connections for unsecured networks like VPN connection, proxy and unsecured Wi-Fi connections.77~@*/
        networkChangeReceiver = NetworkChangeReceiver()
        val filter = IntentFilter(ConnectivityManager.CONNECTIVITY_ACTION)
        registerReceiver(networkChangeReceiver, filter)

        // Initialize SecurityChecker with all checks in warning mode
        securityChecker = SecurityChecker(this, SecurityChecker.SecurityConfig(
            treatRootAsWarning = true,
            treatDeveloperOptionsAsWarning = true,
            treatMalwareAsWarning = true,
            treatTamperingAsWarning = true
        ))
        
        setupButtons()
        performInitialSecurityChecks()
    }

    private fun setupButtons() {
        binding.btnCheckRoot.setOnClickListener { checkRoot() }
        binding.btnCheckDeveloper.setOnClickListener { checkDeveloperOptions() }
        binding.btnCheckNetwork.setOnClickListener { checkNetwork() }
        binding.btnCheckMalware.setOnClickListener { checkMalware() }
        binding.btnCheckScreenMirroring.setOnClickListener { checkScreenMirroring() }
        binding.btnAppSpoofing.setOnClickListener { checkApplicationSpoofing() }
        binding.btnKeyLoggerDetection.setOnClickListener { checkKeyLoggerDetection() }
    }

    private fun performInitialSecurityChecks() {
        // Check for root status on app launch
        when (val result = securityChecker.checkRootStatus()) {
            is SecurityChecker.SecurityCheck.Critical -> {
                SecurityChecker.showSecurityDialog(this, result.message, true)
            }
            is SecurityChecker.SecurityCheck.Warning -> {
                SecurityChecker.showSecurityDialog(this, result.message, false)
            }
            else -> checkDeveloperOptions()
        }
    }

    private fun checkRoot() {

      /*  if(RootUtil.isDeviceRooted){
            showToast(getString(R.string.rooted_message))
        }*/
        when (val result = securityChecker.checkRootStatus()) {
            is SecurityChecker.SecurityCheck.Critical -> {
                SecurityChecker.showSecurityDialog(this, result.message, true)
            }
            is SecurityChecker.SecurityCheck.Warning -> {
                SecurityChecker.showSecurityDialog(this, result.message, false)
            }
            is SecurityChecker.SecurityCheck.Success -> {
                Toast.makeText(this, "Device is not rooted", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun tapJacking() {
        when (val result = securityChecker.checkRootStatus()) {
            is SecurityChecker.SecurityCheck.Critical -> {
                SecurityChecker.showSecurityDialog(this, result.message, true)
            }
            is SecurityChecker.SecurityCheck.Warning -> {
                SecurityChecker.showSecurityDialog(this, result.message, false)
            }
            is SecurityChecker.SecurityCheck.Success -> {
                Toast.makeText(this, "Device is not rooted", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun checkDeveloperOptions() {
        when (val result = securityChecker.checkDeveloperOptions()) {
            is SecurityChecker.SecurityCheck.Critical -> {
                SecurityChecker.showSecurityDialog(this, result.message, true)
            }
            is SecurityChecker.SecurityCheck.Warning -> {
                SecurityChecker.showSecurityDialog(this, result.message, false)
            }
            is SecurityChecker.SecurityCheck.Success -> {
                Toast.makeText(this, "Developer options check passed", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun checkNetwork() {
        when (val result = securityChecker.checkNetworkSecurity()) {
            is SecurityChecker.SecurityCheck.Warning -> {
                SecurityChecker.showSecurityDialog(this, result.message, false)
            }
            is SecurityChecker.SecurityCheck.Success -> {
                Toast.makeText(this, "Network security check passed", Toast.LENGTH_SHORT).show()
            }
            else -> {}
        }
    }

    private fun checkMalware() {
        when (val result = securityChecker.checkMalwareAndTampering()) {
            is SecurityChecker.SecurityCheck.Critical -> {
                SecurityChecker.showSecurityDialog(this, result.message, true)
            }
            is SecurityChecker.SecurityCheck.Warning -> {
                SecurityChecker.showSecurityDialog(this, result.message, false)
            }
            is SecurityChecker.SecurityCheck.Success -> {
                Toast.makeText(this, "Malware check passed", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun checkScreenMirroring() {
        when (val result = securityChecker.checkScreenMirroring()) {
            is SecurityChecker.SecurityCheck.Warning -> {
                SecurityChecker.showSecurityDialog(this, result.message, false)
            }
            is SecurityChecker.SecurityCheck.Success -> {
                Toast.makeText(this, "Screen mirroring check passed", Toast.LENGTH_SHORT).show()
            }
            else -> {}
        }
    }
    private fun checkApplicationSpoofing() {
        when (val result = securityChecker.checkAppSpoofing()) {
            is SecurityChecker.SecurityCheck.Warning -> {
                SecurityChecker.showSecurityDialog(this, result.message, false)
            }
            is SecurityChecker.SecurityCheck.Success -> {
                Toast.makeText(this, "App Spoofing check passed", Toast.LENGTH_SHORT).show()
            }
            else -> {}
        }
    }
    private fun checkKeyLoggerDetection() {
        when (val result = securityChecker.checkKeyLoggerDetection()) {
            is SecurityChecker.SecurityCheck.Warning -> {
                SecurityChecker.showSecurityDialog(this, result.message, false)
            }
            is SecurityChecker.SecurityCheck.Success -> {
                Toast.makeText(this, "Key logger detection check passed", Toast.LENGTH_SHORT).show()
            }
            else -> {}
        }
    }
}
