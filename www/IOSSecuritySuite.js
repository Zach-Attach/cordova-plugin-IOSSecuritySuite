var exec = require("cordova/exec");

module.exports = {
  isRooted: function (onSuccess, onError) {
    exec(onSuccess, onError, "IOSSecuritySuite", "isRooted", []);
  },
};
