package com.webileapps.safeguard;

import android.content.Context;
import android.widget.Toast;
import java.util.function.Consumer;

public class CyberUtils {
    public static void showToast(Context context, String message) {
        Toast.makeText(context, message, Toast.LENGTH_SHORT).show();
    }

    public static void checkRoot(Context context, SecurityChecker securityChecker, Consumer<Boolean> onChecked) {
        SecurityChecker.SecurityCheck result = securityChecker.checkRootStatus();
        if (result instanceof SecurityChecker.SecurityCheck.Critical) {
            SecurityChecker.SecurityCheck.Critical critical = (SecurityChecker.SecurityCheck.Critical) result;
            SecurityConfigManager.getSecurityChecker().showSecurityDialog(
                AppActivity.getContext(), 
                critical.message, 
                true,
                null
            );
            onChecked.accept(false);
        } else if (result instanceof SecurityChecker.SecurityCheck.Warning) {
            SecurityChecker.SecurityCheck.Warning warning = (SecurityChecker.SecurityCheck.Warning) result;
            SecurityConfigManager.getSecurityChecker().showSecurityDialog(
                AppActivity.getContext(), 
                warning.message, 
                false,
                userAcknowledged -> {
                    if (userAcknowledged) {
                        onChecked.accept(true);
                    }
                }
            );
        } else {
            onChecked.accept(true);
        }
    }

    public static void checkDeveloperOptions(Context context, SecurityChecker securityChecker, Consumer<Boolean> onChecked) {
        SecurityChecker.SecurityCheck result = securityChecker.checkDeveloperOptions();
        if (result instanceof SecurityChecker.SecurityCheck.Critical) {
            SecurityChecker.SecurityCheck.Critical critical = (SecurityChecker.SecurityCheck.Critical) result;
            SecurityConfigManager.getSecurityChecker().showSecurityDialog(
                AppActivity.getContext(), 
                critical.message, 
                true,
                null
            );
            onChecked.accept(false);
        } else if (result instanceof SecurityChecker.SecurityCheck.Warning) {
            SecurityChecker.SecurityCheck.Warning warning = (SecurityChecker.SecurityCheck.Warning) result;
            SecurityConfigManager.getSecurityChecker().showSecurityDialog(
                AppActivity.getContext(), 
                warning.message, 
                false,
                userAcknowledged -> {
                    if (userAcknowledged) {
                        onChecked.accept(true);
                    }
                }
            );
        } else {
            onChecked.accept(true);
        }
    }

    public static void checkMalware(Context context, SecurityChecker securityChecker, Consumer<Boolean> onChecked) {
        SecurityChecker.SecurityCheck result = securityChecker.checkMalwareAndTampering();
        if (result instanceof SecurityChecker.SecurityCheck.Critical) {
            SecurityChecker.SecurityCheck.Critical critical = (SecurityChecker.SecurityCheck.Critical) result;
            SecurityConfigManager.getSecurityChecker().showSecurityDialog(
                AppActivity.getContext(), 
                critical.message, 
                true,
                null
            );
        } else if (result instanceof SecurityChecker.SecurityCheck.Warning) {
            SecurityChecker.SecurityCheck.Warning warning = (SecurityChecker.SecurityCheck.Warning) result;
            SecurityConfigManager.getSecurityChecker().showSecurityDialog(
                AppActivity.getContext(), 
                warning.message, 
                false,
                userAcknowledged -> {
                    if (userAcknowledged) {
                        onChecked.accept(true);
                    }
                }
            );
        } else {
            onChecked.accept(true);
        }
    }

    public static void checkScreenMirroring(Context context, SecurityChecker securityChecker, Consumer<Boolean> onChecked) {
        SecurityChecker.SecurityCheck result = securityChecker.checkScreenMirroring();
        if (result instanceof SecurityChecker.SecurityCheck.Warning) {
            SecurityChecker.SecurityCheck.Warning warning = (SecurityChecker.SecurityCheck.Warning) result;
            SecurityConfigManager.getSecurityChecker().showSecurityDialog(
                AppActivity.getContext(), 
                warning.message, 
                false,
                userAcknowledged -> {
                    if (userAcknowledged) {
                        onChecked.accept(true);
                    }
                }
            );
        } else {
            onChecked.accept(true);
        }
    }

    public static void checkApplicationSpoofing(Context context, SecurityChecker securityChecker, Consumer<Boolean> onChecked) {
        SecurityChecker.SecurityCheck result = securityChecker.checkAppSpoofing();
        if (result instanceof SecurityChecker.SecurityCheck.Warning) {
            SecurityChecker.SecurityCheck.Warning warning = (SecurityChecker.SecurityCheck.Warning) result;
            SecurityConfigManager.getSecurityChecker().showSecurityDialog(
                AppActivity.getContext(), 
                warning.message, 
                false,
                userAcknowledged -> {
                    if (userAcknowledged) {
                        onChecked.accept(true);
                    }
                }
            );
        } else {
            onChecked.accept(true);
        }
    }

    public static void checkKeyLoggerDetection(Context context, SecurityChecker securityChecker, Consumer<Boolean> onChecked) {
        SecurityChecker.SecurityCheck result = securityChecker.checkKeyLoggerDetection();
        if (result instanceof SecurityChecker.SecurityCheck.Warning) {
            SecurityChecker.SecurityCheck.Warning warning = (SecurityChecker.SecurityCheck.Warning) result;
            SecurityConfigManager.getSecurityChecker().showSecurityDialog(
                AppActivity.getContext(), 
                warning.message, 
                false,
                userAcknowledged -> {
                    if (userAcknowledged) {
                        onChecked.accept(true);
                    }
                }
            );
        } else {
            onChecked.accept(true);
        }
    }

    public static void appSignatureCheck(Context context, SecurityChecker securityChecker, Consumer<Boolean> onChecked) {
        SecurityChecker.SecurityCheck result = securityChecker.appSignatureCompare();
        if (result instanceof SecurityChecker.SecurityCheck.Warning) {
            SecurityChecker.SecurityCheck.Warning warning = (SecurityChecker.SecurityCheck.Warning) result;
            SecurityConfigManager.getSecurityChecker().showSecurityDialog(
                AppActivity.getContext(), 
                warning.message, 
                false,
                userAcknowledged -> {
                    if (userAcknowledged) {
                        onChecked.accept(true);
                    }
                }
            );
        } else {
            onChecked.accept(true);
        }
    }

    public static void checkInvoiceCall(Context context, SecurityChecker securityChecker, boolean inCall, Consumer<Boolean> onChecked) {
        if (inCall) {
            SecurityConfigManager.getSecurityChecker().showSecurityDialog(
                AppActivity.getContext(),
                context.getString(R.string.ongoing_call_warning),
                false,
                userAcknowledged -> {
                    if (userAcknowledged) {
                        onChecked.accept(true);
                    }
                }
            );
        } else {
            onChecked.accept(true);
        }
    }

    public static void checkNetwork(Context context, SecurityChecker securityChecker, Consumer<Boolean> onChecked) {
        SecurityChecker.SecurityCheck result = securityChecker.checkNetworkSecurity();
        if (result instanceof SecurityChecker.SecurityCheck.Warning) {
            SecurityChecker.SecurityCheck.Warning warning = (SecurityChecker.SecurityCheck.Warning) result;
            SecurityConfigManager.getSecurityChecker().showSecurityDialog(
                AppActivity.getContext(), 
                warning.message, 
                false,
                userAcknowledged -> {
                    if (userAcknowledged) {
                        onChecked.accept(true);
                    }
                }
            );
        } else {
            onChecked.accept(true);
        }
    }

    public static void showSecurityDialogForCheck(Context context, SecurityChecker.SecurityCheck checkResult, boolean isCritical, Consumer<Boolean> onResponse) {
        if (checkResult instanceof SecurityChecker.SecurityCheck.Critical) {
            SecurityChecker.SecurityCheck.Critical critical = (SecurityChecker.SecurityCheck.Critical) checkResult;
            SecurityConfigManager.getSecurityChecker().showSecurityDialog(
                context,
                critical.message,
                true,
                null
            );
        } else if (checkResult instanceof SecurityChecker.SecurityCheck.Warning) {
            SecurityChecker.SecurityCheck.Warning warning = (SecurityChecker.SecurityCheck.Warning) checkResult;
            SecurityConfigManager.getSecurityChecker().showSecurityDialog(
                context,
                warning.message,
                false,
                onResponse
            );
        }
    }
}
