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