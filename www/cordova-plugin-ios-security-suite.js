var exec = require("cordova/exec");

const IOSSecuritySuite = {
  isRooted: function (arg0, success, error) {
    exec(success, error, "IOSSecuritySuite", "isRooted", [arg0]);
  },
};

export default IOSSecuritySuite;
