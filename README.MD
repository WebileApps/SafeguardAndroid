This repository provides an Android security library to easily integrate security checks into Android applications. Its primary goal is to enhance application security, and it is designed to help developers meet common mobile application security regulatory guidelines.

The library offers a comprehensive suite of security functionalities designed to protect applications from common threats. Key security checks include root detection, developer options detection, malware and tampering detection, network security assessments (such as identifying VPN, proxy, or unsecured Wi-Fi connections), screen mirroring and sharing detection, app spoofing prevention, and keylogger detection. These features work together to identify and mitigate potential security vulnerabilities, thereby strengthening the overall security posture of the application.

## Key Components

The repository primarily consists of the following:

*   **`protect/`**: This is the core Android security library, containing all the native code for security checks.
*   **`app/`**: This directory provides a sample native Android application demonstrating the integration and usage of the `protect` library.

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

## License

MIT License