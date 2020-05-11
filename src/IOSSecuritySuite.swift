import Foundation
import JailbreakChecker

@objc(IOSSecuritySuite) class IOSSecuritySuite: CDVPlugin{
    func isRooted(command: CDVInvokedUrlCommand) {
        var pluginResult = CDVPluginResult(
            status: CDVCommandStatus_OK,
            messageAsBool: JailbreakChecker.amIJailbroken()
        )
        self.commandDelegate!.send(
            pluginResult,
            callbackId: command.callbackId
        )
    }
}