var exec = require('cordova/exec');

var Safeguard = {
    SecurityCheckState: {
        ERROR: 'ERROR',
        WARNING: 'WARNING',
        DISABLED: 'DISABLED'
    },

    startSecurityChecks: function(success, error) {
        exec(success, error, 'Safeguard', 'startSecurityChecks', []);
    },

    checkRoot: function(success, error) {
        exec(success, error, 'Safeguard', 'checkRoot', []);
    },

    checkDeveloperOptions: function(success, error) {
        exec(success, error, 'Safeguard', 'checkDeveloperOptions', []);
    },

    checkMalware: function(success, error) {
        exec(success, error, 'Safeguard', 'checkMalware', []);
    },

    checkNetwork: function(success, error) {
        exec(success, error, 'Safeguard', 'checkNetwork', []);
    },

    checkScreenMirroring: function(success, error) {
        exec(success, error, 'Safeguard', 'checkScreenMirroring', []);
    },

    checkAppSpoofing: function(success, error) {
        exec(success, error, 'Safeguard', 'checkAppSpoofing', []);
    },

    checkKeyLogger: function(success, error) {
        exec(success, error, 'Safeguard', 'checkKeyLogger', []);
    },

    checkAll: function(success, error) {
        var results = {};
        var checksCompleted = 0;
        var totalChecks = 7;

        function checkComplete() {
            checksCompleted++;
            if (checksCompleted === totalChecks) {
                success(results);
            }
        }

        this.checkRoot(
            function(result) {
                results.root = { status: 'success', message: result };
                checkComplete();
            },
            function(error) {
                results.root = { status: 'error', message: error };
                checkComplete();
            }
        );

        this.checkDeveloperOptions(
            function(result) {
                results.developerOptions = { status: 'success', message: result };
                checkComplete();
            },
            function(error) {
                results.developerOptions = { status: 'error', message: error };
                checkComplete();
            }
        );

        this.checkMalware(
            function(result) {
                results.malware = { status: 'success', message: result };
                checkComplete();
            },
            function(error) {
                results.malware = { status: 'error', message: error };
                checkComplete();
            }
        );

        this.checkNetwork(
            function(result) {
                results.network = { status: 'success', message: result };
                checkComplete();
            },
            function(error) {
                results.network = { status: 'error', message: error };
                checkComplete();
            }
        );

        this.checkScreenMirroring(
            function(result) {
                results.screenMirroring = { status: 'success', message: result };
                checkComplete();
            },
            function(error) {
                results.screenMirroring = { status: 'error', message: error };
                checkComplete();
            }
        );

        this.checkAppSpoofing(
            function(result) {
                results.appSpoofing = { status: 'success', message: result };
                checkComplete();
            },
            function(error) {
                results.appSpoofing = { status: 'error', message: error };
                checkComplete();
            }
        );

        this.checkKeyLogger(
            function(result) {
                results.keyLogger = { status: 'success', message: result };
                checkComplete();
            },
            function(error) {
                results.keyLogger = { status: 'error', message: error };
                checkComplete();
            }
        );
    }
};

module.exports = Safeguard;
