import Foundation

@objc(IOSSecuritySuite) class IOSSecuritySuite: CDVPlugin{
    @objc(isRooted:) func isRooted(command: CDVInvokedUrlCommand) {
        var pluginResult = CDVPluginResult(
            status: CDVCommandStatus_OK,
            messageAs: JailbreakChecker.amIJailbroken()
        )
        self.commandDelegate!.send(
            pluginResult,
            callbackId: command.callbackId
        )
    }
}