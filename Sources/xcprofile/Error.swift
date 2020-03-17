import Foundation

struct SecurityError: Error, CustomDebugStringConvertible {
    var status: OSStatus
    var developerDescription: String
    
    var debugDescription: String {
        var customDebugDescription = "SecurityError: developerDescription=\(developerDescription)"
        if let securityErrorMessage = SecCopyErrorMessageString(status, nil) {
            customDebugDescription += "\nApple Security Message: \(securityErrorMessage)"
        }
        return customDebugDescription
    }
}
