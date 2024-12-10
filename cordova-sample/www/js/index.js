document.addEventListener('deviceready', onDeviceReady, false);

function onDeviceReady() {
    // Add click listeners to all buttons
    document.getElementById('btnCheckRoot').addEventListener('click', checkRoot);
    document.getElementById('btnCheckDeveloper').addEventListener('click', checkDeveloperOptions);
    document.getElementById('btnCheckNetwork').addEventListener('click', checkNetwork);
    document.getElementById('btnCheckMalware').addEventListener('click', checkMalware);
    document.getElementById('btnCheckScreenMirroring').addEventListener('click', checkScreenMirroring);

    // Perform initial security check
    performInitialSecurityCheck();
}

function performInitialSecurityCheck() {
    SecurityChecker.checkSecurity(
        function(result) {
            let hasWarnings = false;
            let hasCritical = false;
            let messages = [];

            Object.keys(result).forEach(function(check) {
                if (result[check].status === 'critical') {
                    hasCritical = true;
                    messages.push(`Critical: ${result[check].message}`);
                } else if (result[check].status === 'warning') {
                    hasWarnings = true;
                    messages.push(`Warning: ${result[check].message}`);
                }
            });

            if (hasCritical || hasWarnings) {
                showStatus(messages.join('\n'), hasCritical ? 'critical' : 'warning');
            }
        },
        function(error) {
            showStatus('Error performing security checks: ' + error, 'critical');
        }
    );
}

function checkRoot() {
    SecurityChecker.checkRoot(
        function(result) {
            handleSecurityResult(result, 'Root Check');
        },
        function(error) {
            showStatus('Error checking root status: ' + error, 'critical');
        }
    );
}

function checkDeveloperOptions() {
    SecurityChecker.checkDeveloperOptions(
        function(result) {
            handleSecurityResult(result, 'Developer Options Check');
        },
        function(error) {
            showStatus('Error checking developer options: ' + error, 'critical');
        }
    );
}

function checkNetwork() {
    SecurityChecker.checkNetwork(
        function(result) {
            handleSecurityResult(result, 'Network Security Check');
        },
        function(error) {
            showStatus('Error checking network security: ' + error, 'critical');
        }
    );
}

function checkMalware() {
    SecurityChecker.checkMalware(
        function(result) {
            handleSecurityResult(result, 'Malware Check');
        },
        function(error) {
            showStatus('Error checking for malware: ' + error, 'critical');
        }
    );
}

function checkScreenMirroring() {
    SecurityChecker.checkScreenMirroring(
        function(result) {
            handleSecurityResult(result, 'Screen Mirroring Check');
        },
        function(error) {
            showStatus('Error checking screen mirroring: ' + error, 'critical');
        }
    );
}

function handleSecurityResult(result, checkName) {
    if (result.status === 'success') {
        showStatus(`${checkName}: All checks passed`, 'success');
    } else {
        showStatus(`${checkName}: ${result.message}`, result.status);
    }
}

function showStatus(message, status) {
    const statusContainer = document.getElementById('statusContainer');
    const statusMessage = document.getElementById('statusMessage');
    
    // Remove existing status classes
    statusContainer.classList.remove('status-success', 'status-warning', 'status-critical');
    
    // Add new status class
    statusContainer.classList.add(`status-${status}`);
    
    // Update message and show container
    statusMessage.textContent = message;
    statusContainer.style.display = 'block';
}
