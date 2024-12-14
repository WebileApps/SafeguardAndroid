package com.kfintech.protect.sample

import android.content.IntentFilter
import android.net.ConnectivityManager
import android.os.Bundle
import android.util.Log
import android.widget.Toast
import com.kfintech.protect.AppActivity
import com.kfintech.protect.NetworkChangeReceiver
import com.kfintech.protect.SecurityChecker
import com.kfintech.protect.SecurityConfigManager
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
        // Initialize SecurityConfigManager with desired configuration
        SecurityConfigManager.initialize(
            this,
            SecurityChecker.SecurityConfig(
                rootCheck = SecurityChecker.SecurityCheckState.WARNING,
                developerOptionsCheck = SecurityChecker.SecurityCheckState.WARNING,
                malwareCheck = SecurityChecker.SecurityCheckState.WARNING,
                tamperingCheck = SecurityChecker.SecurityCheckState.WARNING,
                appSpoofingCheck = SecurityChecker.SecurityCheckState.WARNING,
                networkSecurityCheck = SecurityChecker.SecurityCheckState.WARNING,
                screenSharingCheck = SecurityChecker.SecurityCheckState.WARNING,
                keyloggerCheck = SecurityChecker.SecurityCheckState.WARNING
            )
        )

        // Get the shared SecurityChecker instance
        securityChecker = SecurityConfigManager.getSecurityChecker()

        networkChangeReceiver = NetworkChangeReceiver()
        val filter = IntentFilter(ConnectivityManager.CONNECTIVITY_ACTION)
        registerReceiver(networkChangeReceiver, filter)
        
        setupButtons()
    }

    private fun setupButtons() {
        // Update button click handlers to use lambda for better readability
        binding.btnCheckRoot.setOnClickListener { 
            this.checkRoot(securityChecker) { success ->
                logCheckResult("Root", success)
            }
        }
        binding.btnCheckDeveloper.setOnClickListener { 
            this.checkDeveloperOptions(securityChecker) { success ->
                logCheckResult("Developer Options", success)
            }
        }
        binding.btnCheckNetwork.setOnClickListener { 
            this.checkNetwork(securityChecker) { success ->
                logCheckResult("Network", success)
            }
        }
        binding.btnCheckMalware.setOnClickListener { 
            this.checkMalware(securityChecker) { success ->
                logCheckResult("Malware", success)
            }
        }
        binding.btnCheckScreenMirroring.setOnClickListener { 
            this.checkScreenMirroring(securityChecker) { success ->
                logCheckResult("Screen Mirroring", success)
            }
        }
        binding.btnAppSpoofing.setOnClickListener { 
            this.checkApplicationSpoofing(securityChecker) { success ->
                logCheckResult("App Spoofing", success)
            }
        }
        binding.btnKeyLoggerDetection.setOnClickListener { 
            this.checkKeyLoggerDetection(securityChecker) { success ->
                logCheckResult("Keylogger", success)
            }
        }
    }

    private fun logCheckResult(checkName: String, success: Boolean) {
        val result = if (success) "passed" else "failed"
        Log.d("SecurityCheck", "$checkName check $result")
    }

    private fun performInitialSecurityChecks() {
        // Perform all security checks in sequence
        this.checkRoot(securityChecker) { rootSuccess ->
            if (!rootSuccess) return@checkRoot
            
            this.checkDeveloperOptions(securityChecker) { devSuccess ->
                if (!devSuccess) return@checkDeveloperOptions
                
                this.checkMalware(securityChecker) { malwareSuccess ->
                    if (!malwareSuccess) return@checkMalware
                    
                    this.checkScreenMirroring(securityChecker) { mirrorSuccess ->
                        if (!mirrorSuccess) return@checkScreenMirroring
                        
                        this.checkApplicationSpoofing(securityChecker) { spoofSuccess ->
                            if (!spoofSuccess) return@checkApplicationSpoofing
                            
                            this.checkKeyLoggerDetection(securityChecker) { keyloggerSuccess ->
                                if (!keyloggerSuccess) return@checkKeyLoggerDetection
                                
                                this.checkNetwork(securityChecker) { networkSuccess ->
                                    if (!networkSuccess) return@checkNetwork
                                    
                                    Log.d("SecurityCheck", "All initial security checks completed successfully")
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
