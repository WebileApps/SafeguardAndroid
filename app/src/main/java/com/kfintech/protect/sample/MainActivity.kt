package com.kfintech.protect.sample

import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.kfintech.protect.SecurityChecker
import com.kfintech.protect.sample.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding
    private lateinit var securityChecker: SecurityChecker

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

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
}
