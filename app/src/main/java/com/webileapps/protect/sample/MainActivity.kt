package com.webileapps.protect.sample

import android.content.IntentFilter
import android.net.ConnectivityManager
import android.os.Bundle
import android.util.Base64
import android.util.Log
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import com.webileapps.safeguard.AppActivity
import com.webileapps.safeguard.NetworkChangeReceiver
import com.webileapps.safeguard.SecurityChecker
import com.webileapps.safeguard.SecurityConfigManager
import com.webileapps.safeguard.CyberUtils
import com.webileapps.protect.sample.databinding.ActivityMainBinding
import java.security.SecureRandom

class MainActivity : AppActivity() {
    private lateinit var binding: ActivityMainBinding
    private lateinit var securityChecker: SecurityChecker
    private lateinit var networkChangeReceiver: NetworkChangeReceiver

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Initialize SecurityConfigManager with desired configuration
        SecurityConfigManager.initialize(
            this,
            SecurityChecker.SecurityConfig(
                SecurityChecker.SecurityCheckState.WARNING,  // rootCheck
                SecurityChecker.SecurityCheckState.DISABLED,  // developerOptionsCheck
                SecurityChecker.SecurityCheckState.ERROR,  // malwareCheck
                SecurityChecker.SecurityCheckState.ERROR,  // tamperingCheck
                SecurityChecker.SecurityCheckState.DISABLED,  // appSpoofingCheck checks package name
                SecurityChecker.SecurityCheckState.DISABLED,  // networkSecurityCheck
                SecurityChecker.SecurityCheckState.ERROR,  // screenSharingCheck
                SecurityChecker.SecurityCheckState.ERROR,  // keyloggerCheck
                SecurityChecker.SecurityCheckState.DISABLED,  // appSignatureCheck
                SecurityChecker.SecurityCheckState.ERROR,  // ongoingCallCheck
                "com.webileapps.protect.sample",            // expectedPackageName
                "2A36434023EECADABE4F43B09C4BF95AB2594256BD0A2577424B85BC2C6E0CBB", // expectedSignature
                "Critical Alert!",                          // criticalDialogTitle
                "Heads Up!",                                // warningDialogTitle
                "Exit App",                                 // criticalDialogPositiveButton
                "Ignore Warning",                           // warningDialogPositiveButton
                "Cancel",                                   // criticalDialogNegativeButton
                null                                         // warningDialogNegativeButton
            )
        )

        // Get the shared SecurityChecker instance
        securityChecker = SecurityConfigManager.getSecurityChecker()

        networkChangeReceiver = NetworkChangeReceiver()
        val filter = IntentFilter(ConnectivityManager.CONNECTIVITY_ACTION)
        registerReceiver(networkChangeReceiver, filter)

        securityChecker.setupCallMonitoring(this) {
            // Handle permission denied
        }

        securityChecker.deviceIntegrity("")


        generateToken()

        setupButtons()
    }

    fun generateNonce(): String? {
        val nonce = ByteArray(32)
        SecureRandom().nextBytes(nonce)

        return Base64.encodeToString(
            nonce,
            Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
        )
    }

    private fun generateToken() {
        val nonce = generateNonce()
        IntegrityManagerFactory.create(applicationContext)
            .requestIntegrityToken(
                IntegrityTokenRequest.builder()
                    .setNonce(nonce)
                    .build()
            )
            .addOnSuccessListener { response ->
                Log.e("PI>>>", "Integrity Token: ${response.token()}")
            }
            .addOnFailureListener { e ->
                Log.e("PI>>>", "Integrity failed: ${e.message}")
            }
    }


    private fun setupButtons() {
        binding.btnCheckRoot.setOnClickListener { 
            CyberUtils.checkRoot(this, securityChecker) { success ->
                logCheckResult("Root", success)
            }
        }

        binding.btnCheckDeveloper.setOnClickListener {
            CyberUtils.checkDeveloperOptions(this, securityChecker) { success ->
                logCheckResult("Developer Options", success)
            }
        }

        binding.btnCheckNetwork.setOnClickListener { 
            CyberUtils.checkNetwork(this, securityChecker) { success ->
                logCheckResult("Network", success)
            }
        }

        binding.btnCheckMalware.setOnClickListener { 
            CyberUtils.checkMalware(this, securityChecker) { success ->
                logCheckResult("Malware", success)
            }
        }

        binding.btnCheckScreenMirroring.setOnClickListener { 
            CyberUtils.checkScreenMirroring(this, securityChecker) { success ->
                logCheckResult("Screen Mirroring", success)
            }
        }

        binding.btnAppSpoofing.setOnClickListener { 
            CyberUtils.checkApplicationSpoofing(this, securityChecker) { success ->
                logCheckResult("App Spoofing", success)
            }
        }

        binding.btnKeyLoggerDetection.setOnClickListener { 
            CyberUtils.checkKeyLoggerDetection(this, securityChecker) { success ->
                logCheckResult("Keylogger", success)
            }
        }
    }

    private fun logCheckResult(checkName: String, success: Boolean) {
        Log.d("SecurityCheck", "$checkName check result: $success")
    }

    override fun onDestroy() {
        super.onDestroy()
        unregisterReceiver(networkChangeReceiver)
    }
}
