## Regulatory Guidelines

1. Mobile application should not work on rooted devices or on simulators.
    Expected response: The mobile application will get closed by prompting user with the message for app closure. Like "Application is not allowed on rooted devices.". Clicking on "OK" will close the application.

1. Device Policy enforcement such as detection of developer option, USB debugging, Mock Location, time settings manipulation, etc. shall be configured.
    Expected response: The mobile application will get closed by prompting user with the message for app closure. Like "Developer option are enabled on this device, which is not allowed. Please disable it to continue using the application.". Clicking on "OK" will close the application.

1. Mobile application shall check new network connections or connections for unsecured networks like VPN connection, proxy and unsecured Wi-Fi connections.
    Expected behaviour: The mobile application shall warn the user about the unsecured network and allow user to continue using the application by owning the risk.

1.  Mobile application shall have anti-malware capabilities covering application spoofing, RAT, screen mirroring, overlay malwares, key loggers, tap jacking, etc.
    Expected response: The mobile application will get closed by prompting user with the message for app closure. Like "Application is being blocked due to malware detection. Please uninstall the application.". Clicking on "OK" will close the application.

1. Controls to prevent reverse engineering and application tampering shall be implemented in the mobile applications. These controls shall also validate the signature during runtime for authenticity of the application.
    Expected response: The mobile application will get closed by prompting user with the message for app closure. Like "Application signature is not as expected. Please uninstall the application and install the application from Google Play Store.". Clicking on "OK" will close the application.

1.  Mobile application shall perform checksum validation and the checksum of applications shall be published in public domain.
    Expected behaviour: The mobile application will get closed by prompting with the message that the checksum is not valid.

1. Mobile application shall identify the presence of active remote access, screen mirroring, active voice call, alert users, etc. to prevent online frauds.
    Expected behaviour: The mobile application shall warn the user about the presence of screen mirroring and allow the user to continue using the application by owning the risk.

# Safeguard Android Security Library

A comprehensive Android security library that provides various security checks and protections for your Android applications.

## Features

- Root Detection
- Developer Options Detection
- Malware Detection
- Network Security
- Screen Mirroring Detection
- App Spoofing Detection
- Keylogger Detection

## Installation

### Gradle

1. Add JitPack repository to your root build.gradle:

```gradle
allprojects {
    repositories {
        ...
        maven { url 'https://jitpack.io' }
    }
}
```

2. Add the dependency to your app's build.gradle:

```gradle
dependencies {
    implementation 'com.github.webileapps:safeguard:0.1.0'
}
```

### Cordova Plugin

```bash
cordova plugin add cordova-plugin-security-checker
```

## Usage

### Android

```kotlin
import com.webileapps.safeguard.*

class MainActivity : AppActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Initialize security config
        SecurityConfigManager.initialize(this)
        
        // Perform security checks
        val isRooted = checkRoot(this)
        val hasDeveloperOptions = checkDeveloperOptions(this)
        val hasMalware = checkMalware(this)
        val isNetworkSecure = checkNetwork(this)
        val isScreenMirroring = checkScreenMirroring(this)
        val isAppSpoofed = checkApplicationSpoofing(this)
        val hasKeyLogger = checkKeyLoggerDetection(this)
    }
}
```

### Cordova

```javascript
// Check all security features
SecurityChecker.checkSecurity(
    function(result) {
        console.log('Security check passed:', result);
    },
    function(error) {
        console.error('Security check failed:', error);
    }
);

// Individual checks
SecurityChecker.checkRoot(successCallback, errorCallback);
SecurityChecker.checkDeveloperOptions(successCallback, errorCallback);
SecurityChecker.checkMalware(successCallback, errorCallback);
SecurityChecker.checkNetwork(successCallback, errorCallback);
SecurityChecker.checkScreenMirroring(successCallback, errorCallback);
SecurityChecker.checkApplicationSpoofing(successCallback, errorCallback);
SecurityChecker.checkKeyLogger(successCallback, errorCallback);
```

## Configuration

### Cordova config.xml

```xml
<preference name="ROOT_CHECK_STATE" value="ERROR" />
<preference name="DEVELOPER_OPTIONS_CHECK_STATE" value="WARNING" />
<preference name="MALWARE_CHECK_STATE" value="ERROR" />
<preference name="TAMPERING_CHECK_STATE" value="ERROR" />
<preference name="NETWORK_SECURITY_CHECK_STATE" value="WARNING" />
<preference name="SCREEN_SHARING_CHECK_STATE" value="WARNING" />
<preference name="APP_SPOOFING_CHECK_STATE" value="ERROR" />
<preference name="KEYLOGGER_CHECK_STATE" value="ERROR" />
```

Values can be: `ERROR`, `WARNING`, or `DISABLED`

## License

MIT License