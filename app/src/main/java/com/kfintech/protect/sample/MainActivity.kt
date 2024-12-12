package com.kfintech.protect.sample

import android.content.IntentFilter
import android.net.ConnectivityManager
import android.os.Bundle
import android.util.Log
import android.widget.Toast
import com.kfintech.protect.AppActivity
import com.kfintech.protect.NetworkChangeReceiver
import com.kfintech.protect.SecurityChecker
import com.kfintech.protect.checkApplicationSpoofing
import com.kfintech.protect.checkDeveloperOptions
import com.kfintech.protect.checkKeyLoggerDetection
import com.kfintech.protect.checkMalware
import com.kfintech.protect.checkNetwork
import com.kfintech.protect.checkRoot
import com.kfintech.protect.checkScreenMirroring
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
        binding.btnCheckRoot.setOnClickListener { this.checkRoot(securityChecker,{}) }
        binding.btnCheckDeveloper.setOnClickListener { this.checkDeveloperOptions(securityChecker,{}) }
        binding.btnCheckNetwork.setOnClickListener { this.checkNetwork(securityChecker,{}) }
        binding.btnCheckMalware.setOnClickListener { this.checkMalware(securityChecker,{}) }
        binding.btnCheckScreenMirroring.setOnClickListener { this.checkScreenMirroring(securityChecker,{}) }
        binding.btnAppSpoofing.setOnClickListener { this.checkApplicationSpoofing(securityChecker,{}) }
        binding.btnKeyLoggerDetection.setOnClickListener { this.checkKeyLoggerDetection(securityChecker,{}) }
    }

    private fun performInitialSecurityChecks() {
        // Check for root status on app launch
     /*   when (val result = securityChecker.checkRootStatus()) {
            is SecurityChecker.SecurityCheck.Critical -> {
                SecurityChecker.showSecurityDialog(this, result.message, true)
            }
            is SecurityChecker.SecurityCheck.Warning -> {
                SecurityChecker.showSecurityDialog(this, result.message, false)
            }
            else -> checkDeveloperOptions()
        }*/
    }




}
