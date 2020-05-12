var exec = require("cordova/exec");

module.exports = {
  isRooted: function (onSuccess, onError) {
    exec(
      (res) => {
        console.log("result came back as", res);
        onSuccess(res);
      },
      (err) => {
        console.error("error while executing", err);
        onError(err);
      },
      "IOSSecuritySuite",
      "isRooted",
      []
    );
  },
};
