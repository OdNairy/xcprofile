import Foundation
import Security

func userDefaultKeychain() throws -> SecKeychain {
    try findKeychain(name: "login.keychain")
}

private func findKeychain(name: String) throws -> SecKeychain {
    var searchListCF: CFArray?
    SecKeychainCopyDomainSearchList(.user, &searchListCF)
    
    guard let searchList = searchListCF as? [SecKeychain] else { throw KeychainError.cannotConvertKeychainList }
    
    for keychain in searchList {
        var pathLength: UInt32 = 0
        var pathBuffer = UnsafeMutablePointer<Int8>.allocate(capacity: 0)
    
        SecKeychainGetPath(keychain, &pathLength, pathBuffer)
        pathLength += 1
        pathBuffer = UnsafeMutablePointer<Int8>.allocate(capacity: Int(pathLength))
        SecKeychainGetPath(keychain, &pathLength, pathBuffer)
    
        let keychainURL = URL(fileURLWithPath: String(cString: pathBuffer))
        if keychainURL.lastPathComponent.contains(name) {
            logger.trace("Keychain URL = \(keychainURL.path)", metadata: ["Keychain Name": .string(name)])
            return keychain
        }
    }
    throw KeychainError.noUserKeychainFound
}
