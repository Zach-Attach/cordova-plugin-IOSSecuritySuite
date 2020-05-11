import Foundation

@objc(ModusEchoSwift) class ModusEchoSwift: CDVPlugin{
    func isRooted(command: CDVInvokedUrlCommand) {
        var pluginResult = CDVPluginResult(
            status: CDVCommandStatus_ERROR
        )

        let msg = command.argumends[0] as? String ?? ""

        pluginResult = CDVPluginResult(
            status: CDVCommandStatus_OK,
            messageAsBool: JailbreakChecker.amIJailbroken()
        )
        self.commandDelegate!.send(
            pluginResult,
            callbackId: command.callbackId
        )
    }
}