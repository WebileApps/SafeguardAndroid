var exec = require('cordova/exec');

var SecurityChecker = {
    checkSecurity: function(success, error) {
        exec(success, error, 'SecurityChecker', 'checkSecurity', []);
    },

    checkRoot: function(success, error) {
        exec(success, error, 'SecurityChecker', 'checkRoot', []);
    },

    checkDeveloperOptions: function(success, error) {
        exec(success, error, 'SecurityChecker', 'checkDeveloperOptions', []);
    },

    checkNetwork: function(success, error) {
        exec(success, error, 'SecurityChecker', 'checkNetwork', []);
    },

    checkMalware: function(success, error) {
        exec(success, error, 'SecurityChecker', 'checkMalware', []);
    },

    checkScreenMirroring: function(success, error) {
        exec(success, error, 'SecurityChecker', 'checkScreenMirroring', []);
    }
};

module.exports = SecurityChecker;
