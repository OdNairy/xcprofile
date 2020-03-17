import Foundation
import Security

func userDefaultKeychain() -> SecKeychain? {
    findKeychain(name: "login.keychain")
}

private func findKeychain(name: String) -> SecKeychain? {
    var searchListCF: CFArray?
    SecKeychainCopyDomainSearchList(.user, &searchListCF)
    
    guard let searchList = searchListCF as? [SecKeychain] else { return nil }
    
    for keychain in searchList {
        var pathLength: UInt32 = 0
        var pathBuffer = UnsafeMutablePointer<Int8>.allocate(capacity: 0)
    
        assert(SecKeychainGetPath(keychain, &pathLength, pathBuffer) == errSecBufferTooSmall)
        pathLength += 1
        pathBuffer = UnsafeMutablePointer<Int8>.allocate(capacity: Int(pathLength))
        assert(SecKeychainGetPath(keychain, &pathLength, pathBuffer) == kOSReturnSuccess)
    
        let keychainURL = URL(fileURLWithPath: String(cString: pathBuffer))
        
        if keychainURL.lastPathComponent.contains(name) {
            return keychain
        }
    }
    return nil
}
