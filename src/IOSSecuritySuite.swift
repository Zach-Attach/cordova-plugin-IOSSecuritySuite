import Foundation
import Foundation
import UIKit
import Darwin // fork
import MachO // dyld

@objc(IOSSecuritySuite) class IOSSecuritySuite: CDVPlugin{
    @objc(isRooted:)
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


public typealias FailedCheck = (check: JailbreakCheck, failMessage: String)

public enum JailbreakCheck: CaseIterable {
    case urlSchemes
    case existenceOfSuspiciousFiles
    case suspiciousFilesCanBeOpened
    case restrictedDirectoriesWriteable
    case fork
    case symbolicLinks
    case dyld
}

internal class JailbreakChecker {
    typealias CheckResult = (passed: Bool, failMessage: String)

    struct JailbreakStatus {
        let passed: Bool
        let failMessage: String // Added for backwards compatibility
        let failedChecks: [FailedCheck]
    }

    static func amIJailbroken() -> Bool {
        return !performChecks().passed
    }

    static func amIJailbrokenWithFailMessage() -> (jailbroken: Bool, failMessage: String) {
        let status = performChecks()
        return (!status.passed, status.failMessage)
    }

    static func amIJailbrokenWithFailedChecks() -> (jailbroken: Bool, failedChecks: [FailedCheck]) {
        let status = performChecks()
        return (!status.passed, status.failedChecks)
    }

    private static func performChecks() -> JailbreakStatus {
        var passed = true
        var failMessage = ""
        var result: CheckResult = (true, "")
        var failedChecks: [FailedCheck] = []

        for check in JailbreakCheck.allCases {
            switch check {
            case .urlSchemes:
                result = checkURLSchemes()
            case .existenceOfSuspiciousFiles:
                result = checkExistenceOfSuspiciousFiles()
            case .suspiciousFilesCanBeOpened:
                result = checkSuspiciousFilesCanBeOpened()
            case .restrictedDirectoriesWriteable:
                result = checkRestrictedDirectoriesWriteable()
            case .fork:
                if !EmulatorChecker.amIRunInEmulator() {
                    result = checkFork()
                } else {
                    print("App run in the emulator, skipping the fork check.")
                    result = (true, "")
                }
            case .symbolicLinks:
                result = checkSymbolicLinks()
            case .dyld:
                result = checkDYLD()
            }

            passed = passed && result.passed

            if !result.passed {
                failedChecks.append((check: check, failMessage: result.failMessage))

                if !failMessage.isEmpty {
                    failMessage += ", "
                }
            }

            failMessage += result.failMessage
        }

        return JailbreakStatus(passed: passed, failMessage: failMessage, failedChecks: failedChecks)
    }

    private static func canOpenUrlFromList(urlSchemes: [String]) -> CheckResult {
        for urlScheme in urlSchemes {
            if let url = URL(string: urlScheme) {
                if UIApplication.shared.canOpenURL(url) {
                    return(false, "\(urlScheme) URL scheme detected")
                }
            }
        }
        return (true, "")
    }

    private static func checkURLSchemes() -> CheckResult {
        var flag: (passed: Bool, failMessage: String) = (true, "")
        let urlSchemes = [
            "undecimus://",
            "cydia://",
            "sileo://",
            "zbra://"
        ]

        if Thread.isMainThread {
            flag = canOpenUrlFromList(urlSchemes: urlSchemes)
        } else {
            let semaphore = DispatchSemaphore(value: 0)
            DispatchQueue.main.async {
                flag = canOpenUrlFromList(urlSchemes: urlSchemes)
                semaphore.signal()
            }
            semaphore.wait()
        }
        return flag
    }

    private static func checkExistenceOfSuspiciousFiles() -> CheckResult {
        var paths = [
            "/usr/sbin/frida-server", // frida
            "/etc/apt/sources.list.d/electra.list", // electra
            "/etc/apt/sources.list.d/sileo.sources", // electra
            "/.bootstrapped_electra", // electra
            "/usr/lib/libjailbreak.dylib", // electra
            "/jb/lzma", // electra
            "/.cydia_no_stash", // unc0ver
            "/.installed_unc0ver", // unc0ver
            "/jb/offsets.plist", // unc0ver
            "/usr/share/jailbreak/injectme.plist", // unc0ver
            "/etc/apt/undecimus/undecimus.list", // unc0ver
            "/var/lib/dpkg/info/mobilesubstrate.md5sums", // unc0ver
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/jb/jailbreakd.plist", // unc0ver
            "/jb/amfid_payload.dylib", // unc0ver
            "/jb/libjailbreak.dylib", // unc0ver
            "/usr/libexec/cydia/firmware.sh",
            "/var/lib/cydia",
            "/etc/apt",
            "/private/var/lib/apt",
            "/private/var/Users/",
            "/var/log/apt",
            "/Applications/Cydia.app",
            "/private/var/stash",
            "/private/var/lib/apt/",
            "/private/var/lib/cydia",
            "/private/var/cache/apt/",
            "/private/var/log/syslog",
            "/private/var/tmp/cydia.log",
            "/Applications/Icy.app",
            "/Applications/MxTube.app",
            "/Applications/RockApp.app",
            "/Applications/blackra1n.app",
            "/Applications/SBSettings.app",
            "/Applications/FakeCarrier.app",
            "/Applications/WinterBoard.app",
            "/Applications/IntelliScreen.app",
            "/private/var/mobile/Library/SBSettings/Themes",
            "/Library/MobileSubstrate/CydiaSubstrate.dylib",
            "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
            "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
            "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
            "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist"
        ]
        
        // These files can give false positive in the emulator
        if !EmulatorChecker.amIRunInEmulator() {
            paths += [
            "/bin/bash",
            "/usr/sbin/sshd",
            "/usr/libexec/ssh-keysign",
            "/bin/sh",
            "/etc/ssh/sshd_config",
            "/usr/libexec/sftp-server",
            "/usr/bin/ssh"
            ]
        }

        for path in paths {
            if FileManager.default.fileExists(atPath: path) {
                return (false, "Suspicious file exists: \(path)")
            }
        }

        return (true, "")
    }

    private static func checkSuspiciousFilesCanBeOpened() -> CheckResult {

        var paths = [
            "/.installed_unc0ver",
            "/.bootstrapped_electra",
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/etc/apt",
            "/var/log/apt"
        ]
        
        // These files can give false positive in the emulator
        if !EmulatorChecker.amIRunInEmulator() {
            paths += [
            "/bin/bash",
            "/usr/sbin/sshd",
            "/usr/bin/ssh"
            ]
        }

        for path in paths {

            if FileManager.default.isReadableFile(atPath: path) {
                return (false, "Suspicious file can be opened: \(path)")
            }
        }

        return (true, "")
    }

    private static func checkRestrictedDirectoriesWriteable() -> CheckResult {

        let paths = [
            "/",
            "/root/",
            "/private/",
            "/jb/"
        ]

        // If library won't be able to write to any restricted directory the return(false, ...) is never reached
        // because of catch{} statement
        for path in paths {
            do {
                let pathWithSomeRandom = path+UUID().uuidString
                try "AmIJailbroken?".write(toFile: pathWithSomeRandom, atomically: true, encoding: String.Encoding.utf8)
                try FileManager.default.removeItem(atPath: pathWithSomeRandom) // clean if succesfully written
                return (false, "Wrote to restricted path: \(path)")
            } catch {}
        }

        return (true, "")
    }

    private static func checkFork() -> CheckResult {

        let pointerToFork = UnsafeMutableRawPointer(bitPattern: -2)
        let forkPtr = dlsym(pointerToFork, "fork")
        typealias ForkType = @convention(c) () -> pid_t
        let fork = unsafeBitCast(forkPtr, to: ForkType.self)
        let forkResult = fork()

        if forkResult >= 0 {
            if forkResult > 0 {
                kill(forkResult, SIGTERM)
            }
            return (false, "Fork was able to create a new process (sandbox violation)")
        }

        return (true, "")
    }

    private static func checkSymbolicLinks() -> CheckResult {

        let paths = [
            "/var/lib/undecimus/apt", // unc0ver
            "/Applications",
            "/Library/Ringtones",
            "/Library/Wallpaper",
            "/usr/arm-apple-darwin9",
            "/usr/include",
            "/usr/libexec",
            "/usr/share"
        ]

        for path in paths {
            do {
                let result = try FileManager.default.destinationOfSymbolicLink(atPath: path)
                if !result.isEmpty {
                    return (false, "Non standard symbolic link detected: \(path) points to \(result)")
                }
            } catch {}
        }

        return (true, "")
    }

    private static func checkDYLD() -> CheckResult {

        let suspiciousLibraries = [
            "SubstrateLoader.dylib",
            "SSLKillSwitch2.dylib",
            "SSLKillSwitch.dylib",
            "MobileSubstrate.dylib",
            "TweakInject.dylib",
            "CydiaSubstrate",
            "cynject",
            "CustomWidgetIcons",
            "PreferenceLoader",
            "RocketBootstrap",
            "WeeLoader"
        ]

        for libraryIndex in 0..<_dyld_image_count() {

            // _dyld_get_image_name returns const char * that needs to be casted to Swift String
            guard let loadedLibrary = String(validatingUTF8: _dyld_get_image_name(libraryIndex)) else { continue }

            for suspiciousLibrary in suspiciousLibraries {
                if loadedLibrary.lowercased().contains(suspiciousLibrary.lowercased()) {
                    return(false, "Suspicious library loaded: \(loadedLibrary)")
                }
            }
        }

        return (true, "")
    }
}

internal class EmulatorChecker {

    static func amIRunInEmulator() -> Bool {

        return checkCompile() || checkRuntime()
    }

    private static func checkRuntime() -> Bool {

        return ProcessInfo().environment["SIMULATOR_DEVICE_NAME"] != nil
    }

    private static func checkCompile() -> Bool {

        #if targetEnvironment(simulator)
        return true
        #else
        return false
        #endif
    }

}


internal class DebuggerChecker {

    // https://developer.apple.com/library/archive/qa/qa1361/_index.html
    static func amIDebugged() -> Bool {

        var kinfo = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.stride
        let sysctlRet = sysctl(&mib, UInt32(mib.count), &kinfo, &size, nil, 0)

        if sysctlRet != 0 {
            print("Error occured when calling sysctl(). The debugger check may not be reliable")
        }

        return (kinfo.kp_proc.p_flag & P_TRACED) != 0
    }

    static func denyDebugger() {

        // bind ptrace()
        let pointerToPtrace = UnsafeMutableRawPointer(bitPattern: -2)
        let ptracePtr = dlsym(pointerToPtrace, "ptrace")
        typealias PtraceType = @convention(c) (CInt, pid_t, CInt, CInt) -> CInt
        let ptrace = unsafeBitCast(ptracePtr, to: PtraceType.self)

        // PT_DENY_ATTACH == 31
        let ptraceRet = ptrace(31, 0, 0, 0)

        if ptraceRet != 0 {
            print("Error occured when calling ptrace(). Denying debugger may not be reliable")
        }
    }

}


internal class ReverseEngineeringToolsChecker {

    static func amIReverseEngineered() -> Bool {
        return (checkDYLD() || checkExistenceOfSuspiciousFiles() || checkOpenedPorts() || checkPSelectFlag())
    }

    private static func checkDYLD() -> Bool {

        let suspiciousLibraries = [
            "FridaGadget",
            "frida", // Needle injects frida-somerandom.dylib
            "cynject",
            "libcycript"
        ]

        for libraryIndex in 0..<_dyld_image_count() {

            // _dyld_get_image_name returns const char * that needs to be casted to Swift String
            guard let loadedLibrary = String(validatingUTF8: _dyld_get_image_name(libraryIndex)) else { continue }

            for suspiciousLibrary in suspiciousLibraries {
                if loadedLibrary.lowercased().contains(suspiciousLibrary.lowercased()) {
                    return true
                }
            }
        }

        return false
    }

    private static func checkExistenceOfSuspiciousFiles() -> Bool {

        let paths = [
            "/usr/sbin/frida-server"
        ]

        for path in paths {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
        }

        return false
    }

    private static func checkOpenedPorts() -> Bool {

        let ports = [
            27042, // default Frida
            4444 // default Needle
        ]

        for port in ports {

            if canOpenLocalConnection(port: port) {
                return true
            }
        }

        return false
    }

    private static func canOpenLocalConnection(port: Int) -> Bool {

        func swapBytesIfNeeded(port: in_port_t) -> in_port_t {
            let littleEndian = Int(OSHostByteOrder()) == OSLittleEndian
            return littleEndian ? _OSSwapInt16(port) : port
        }

        var serverAddress = sockaddr_in()
        serverAddress.sin_family = sa_family_t(AF_INET)
        serverAddress.sin_addr.s_addr = inet_addr("127.0.0.1")
        serverAddress.sin_port = swapBytesIfNeeded(port: in_port_t(port))
        let sock = socket(AF_INET, SOCK_STREAM, 0)

        let result = withUnsafePointer(to: &serverAddress) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(sock, $0, socklen_t(MemoryLayout<sockaddr_in>.stride))
            }
        }

        if result != -1 {
            return true // Port is opened
        }

        return false
    }
    
    // EXPERIMENTAL
    private static func checkPSelectFlag() -> Bool {
        var kinfo = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.stride
        let sysctlRet = sysctl(&mib, UInt32(mib.count), &kinfo, &size, nil, 0)

        if sysctlRet != 0 {
            print("Error occured when calling sysctl(). This check may not be reliable")
        }
        
        return (kinfo.kp_proc.p_flag & P_SELECT) != 0
    }
}