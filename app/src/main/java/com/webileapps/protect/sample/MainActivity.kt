package com.webileapps.protect.sample

import android.content.IntentFilter
import android.net.ConnectivityManager
import android.os.Bundle
import android.util.Log
import com.webileapps.safeguard.AppActivity
import com.webileapps.safeguard.NetworkChangeReceiver
import com.webileapps.safeguard.SecurityChecker
import com.webileapps.safeguard.SecurityConfigManager
import com.webileapps.safeguard.checkApplicationSpoofing
import com.webileapps.safeguard.checkDeveloperOptions
import com.webileapps.safeguard.checkKeyLoggerDetection
import com.webileapps.safeguard.checkMalware
import com.webileapps.safeguard.checkNetwork
import com.webileapps.safeguard.checkRoot
import com.webileapps.safeguard.checkScreenMirroring
import com.webileapps.protect.sample.databinding.ActivityMainBinding

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
                keyloggerCheck = SecurityChecker.SecurityCheckState.WARNING,
                ongoingCallCheck = SecurityChecker.SecurityCheckState.WARNING,
                expectedPackageName = "com.webileapps.protect.sample",
                expectedSignature = ""
            )
        )

        // Get the shared SecurityChecker instance
        securityChecker = SecurityConfigManager.getSecurityChecker()

        networkChangeReceiver = NetworkChangeReceiver()
        val filter = IntentFilter(ConnectivityManager.CONNECTIVITY_ACTION)
        registerReceiver(networkChangeReceiver, filter)

        securityChecker.setupCallMonitoring(activity= this, onPermissionDenied = {
        })

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
