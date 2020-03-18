import Foundation
import ArgumentParser
import ZIPFoundation

public class DeveloperEncryptedProfile {
    private(set) var inputURL: URL
    
    public init(url: URL) {
        self.inputURL = url
    }
    
    public func decompress(password: String, output: URL? = nil) throws -> DeveloperDecryptedProfile {
        let output = output ?? FileManager.default.temporaryDirectory.appendingPathComponent(ProcessInfo.processInfo.globallyUniqueString, isDirectory: true)
        if FileManager.default.fileExists(atPath: output.path) {
            try FileManager.default.removeItem(at: output)
        }

        try FileManager.default.unzipItem(at: inputURL, to: output)

        let keychainURL = output.appendingPathComponent("developer/accounts.keychain")
        let accountPlistURL = output.appendingPathComponent("developer/accounts.plist")

        try decipher(inputURL: keychainURL, output: keychainURL, password: password)
        try decipher(inputURL: accountPlistURL, output: accountPlistURL, password: password)
        
        return try DeveloperDecryptedProfile(inputURL: inputURL, outputURL: output, password: password)
    }
}


public class DeveloperDecryptedProfile {
    var keychainURL: URL { outputURL.appendingPathComponent("developer/accounts.keychain") }
    var accountPlistURL: URL { outputURL.appendingPathComponent("developer/accounts.plist") }
    var identitiesFolderURL: URL { outputURL.appendingPathComponent("developer/identities/") }
    var provisionProfilesFolderURL: URL { outputURL.appendingPathComponent("developer/profiles/") }
    
    private var password: String
    var inputURL: URL
    var outputURL: URL
    
    var targetKeychain: SecKeychain

    fileprivate init(inputURL: URL, outputURL: URL, password: String) throws {
        self.inputURL = inputURL
        self.outputURL = outputURL
        self.password = password
        targetKeychain = try userDefaultKeychain()
    }
    
    public func compress(password: String) throws -> DeveloperEncryptedProfile {
        try cipher(inputURL: keychainURL, password: password)
        try cipher(inputURL: accountPlistURL, password: password)
        
        let profileOutputURL = outputURL.appendingPathComponent("developer", isDirectory: true)
        logger.info("Zipping folder \(profileOutputURL.path) to \(inputURL.path)")
        try FileManager.default.removeItem(at: inputURL)
        try FileManager.default.zipItem(at: profileOutputURL, to: inputURL)
        
        return DeveloperEncryptedProfile(url: inputURL)
    }
    
    public func `import`() throws {
        var defaultKeychainUserInteraction: DarwinBoolean = true
        SecKeychainGetUserInteractionAllowed(&defaultKeychainUserInteraction)
        SecKeychainSetUserInteractionAllowed(false)
        defer { SecKeychainSetUserInteractionAllowed(defaultKeychainUserInteraction.boolValue) }

        try importKeychain()
        try importAccountsSettings()
        try importProfiles()
    }
    
    func importKeychain() throws{
        try importTokens()
        try importIdentities()
    }
    
    func importTokens() throws {
        var accountsKeychain: SecKeychain!
        guard SecKeychainOpen(keychainURL.path, &accountsKeychain) == errSecSuccess else { return }
        
        let cPassword = password.cString(using: .utf8)!
        SecKeychainUnlock(accountsKeychain, UInt32(cPassword.count), cPassword, true)
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecMatchSearchList as String: [accountsKeychain] as CFArray
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        if status != errSecSuccess, let errorMessage = SecCopyErrorMessageString(status, nil) as String? {
            logger.error("CopyMatching error: \(errorMessage)")
        }
        
        guard let sourceKeychainItems = item as? [SecKeychainItem] else { throw ExitCode.failure }
        
        // Above - common with re-export command.
        // Below - unique for importTokens function
        
        let secAccess = defaultSecAccessForCodeSigning()
        for keychainItem in sourceKeychainItems {
            var copiedKeychainItem: SecKeychainItem?
            
            let copyStatus = SecKeychainItemCreateCopy(keychainItem, targetKeychain, secAccess, &copiedKeychainItem)
            
            if copyStatus != errSecSuccess {
                let message = SecCopyErrorMessageString(copyStatus, nil)
                print(message ?? "No message for Security error code \(copyStatus)")
            }
        }
    }
    
    func validateTokens() throws -> Bool {
        logger.error("Not implemented yet 😟")
        return false
    }
    
    
    /// This function will remove application-specific restriction in keychain packed inside DeveloperProfile
    /// We need this to allow application with any path to be able to copy tokens to the target keychain
    /// Exported DeveloperProfile still will be encrypted with original password so we assume no security breach will be introduced
    /// The final KeychainItems will be restricted limited to codesign-related applications only.
    /// Check `defaultSecAccessForCodeSigning` for latest application list
    public func reexportKeychain() throws {
        var accountsKeychain: SecKeychain!
        guard SecKeychainOpen(keychainURL.path, &accountsKeychain) == errSecSuccess else { return }
        
        let cPassword = password.cString(using: .utf8)!
        SecKeychainUnlock(accountsKeychain, UInt32(cPassword.count), cPassword, true)
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecMatchSearchList as String: [accountsKeychain] as CFArray
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        if status != errSecSuccess, let errorMessage = SecCopyErrorMessageString(status, nil) as String? {
            logger.error("CopyMatching error: \(errorMessage)")
        }
        
        guard let sourceKeychainItems = item as? [SecKeychainItem] else { throw ExitCode.failure }
        
        for keychainItem in sourceKeychainItems {
            var secAccess: SecAccess!
            SecKeychainItemCopyAccess(keychainItem, &secAccess)
            
            // Look up for SecACL with the next authorizations:
            //    [0] = ACLAuthorizationDecrypt
            //    [1] = ACLAuthorizationDerive
            //    [2] = ACLAuthorizationExportClear
            //    [3] = ACLAuthorizationExportWrapped
            //    [4] = ACLAuthorizationMAC
            //    [5] = ACLAuthorizationSign
            let acls = SecAccessCopyMatchingACLList(secAccess, kSecACLAuthorizationDecrypt) as! [SecACL]
            if let acl = acls.first {
                var applicationList: CFArray?
                var description: CFString!
                var prompt: SecKeychainPromptSelector = .invalidAct
                SecACLCopyContents(acl, &applicationList, &description, &prompt)
                SecACLSetContents(acl, nil, description, prompt)
            } else {
                assertionFailure("No SecACL with specific tag was found")
            }
            
            SecKeychainItemSetAccess(keychainItem, secAccess)
        }
        
        print("Output keychain can be found: \(outputURL.path)")
    }
   
    
    func defaultSecAccessForCodeSigning() -> SecAccess {
        /// This list was taken from fastlane source code.
        /// However, looks like we need nothing but `/usr/bin/xcodebuild`
        let codesigningAppleUtilPaths = ["/usr/bin/codesign", "/usr/bin/security", "/usr/bin/productbuild", "/usr/bin/xcodebuild"]
        return secAccess(for: codesigningAppleUtilPaths)
    }
    
    func secAccess(for applications: [String]?) -> SecAccess {
        let trustedApplications = applications?.map({ path -> SecTrustedApplication in
            var application: SecTrustedApplication!
            SecTrustedApplicationCreateFromPath(path, &application)
            return application
        })
        
        var secAccess: SecAccess!
        SecAccessCreate("Identity" as CFString, trustedApplications.map({ $0 as CFArray }), &secAccess)
        
        return secAccess
    }
    
    func importIdentities() throws {
        let identityFilenames = try FileManager.default.contentsOfDirectory(atPath: identitiesFolderURL.path)
        
        for identityFilename in identityFilenames {
            let identityURL = identitiesFolderURL.appendingPathComponent(identityFilename)
            let identityData = try Data(contentsOf: identityURL)
            let importOptions: [CFString : Any] = [
                kSecImportExportPassphrase: password,
                kSecImportExportKeychain: targetKeychain,
                kSecImportExportAccess: defaultSecAccessForCodeSigning()
            ]
            
            var items: CFArray!
            let importStatus = SecPKCS12Import(identityData as CFData, importOptions as CFDictionary, &items)
            
            if importStatus != errSecSuccess {
                var errorMessage = "Identity import failed (path=\(identityURL.path))"
                
                if let message = SecCopyErrorMessageString(importStatus, nil) {
                    errorMessage += ". Security message: \(message)"
                }
                print(errorMessage)
            }
        }
    }
    
    enum AccountPlistImportError: Error {
        case unsupportedVersion
        case cannotReadAccountPlist
        case cannotReadXcodeDefaults
        case xcodeDefaultsAccountsAreNotAvailable
    }
    
    func importAccountsSettings() throws {
        let supportedAccountPlistVersion = "1"
        let xcodeDefaultsIdentifier = "com.apple.dt.Xcode"
        let xcodeDefaultsAppleIDsKeys = "DVTDeveloperAccountManagerAppleIDLists"
        let xcodeDefaultsIDEProductionSubkey = "IDE.Prod"
        let accountPlistVersionKey = "AccountsPlistVersion"
        let accountPlistArrayKeyPath = "DeveloperAccounts.accounts"
        
        guard let accountsDict = NSDictionary(contentsOf: accountPlistURL) else {
            throw AccountPlistImportError.cannotReadAccountPlist
        }
        guard let xcodeDefaults = UserDefaults(suiteName: xcodeDefaultsIdentifier) else {
            throw AccountPlistImportError.cannotReadXcodeDefaults
        }
        
        guard let plistVersion = accountsDict[accountPlistVersionKey] as? String, plistVersion == supportedAccountPlistVersion else {
            throw AccountPlistImportError.unsupportedVersion
        }
        
        guard let accounts = accountsDict.value(forKeyPath: accountPlistArrayKeyPath) as? [[String: Any]] else {
            throw AccountPlistImportError.xcodeDefaultsAccountsAreNotAvailable
        }
        
        // KVC method 'mutableArrayValue(orKeyPath:)' cannot be use in this scenario
        // The reason is KeyPath 'DVTDeveloperAccountManagerAppleIDLists -> IDE.Prod'
        // Pay attention that the second key contains dot symbol which breaks KeyPath functionality
        // For this reason we have used workaround:
        //      1. Make a mutable copy of Dictionary at key 'DVTDeveloperAccountManagerAppleIDLists'
        //      2. Make a mutable copy of Array at key 'IDE.Prod'
        //      3. Populate mutable array with new records
        //      4. Set updated array to mutable Dictionary at key 'IDE.Prod'
        //      5. Set updated dictionary back to UserDefaults at key 'DVTDeveloperAccountManagerAppleIDLists'
        let originXcodeAppleIDLists = xcodeDefaults.value(forKey: xcodeDefaultsAppleIDsKeys) as! NSDictionary
        let modifiedXcodeAppleIDLists = originXcodeAppleIDLists.mutableCopy() as! NSMutableDictionary
        
        let xcodeAppleIDs = modifiedXcodeAppleIDLists[xcodeDefaultsIDEProductionSubkey] as! [[String:Any]]
        
        let accountNames = accounts.compactMap({ $0["username"] as? String })
        let xcodeAccountNames = xcodeAppleIDs.compactMap({ $0["username"] as? String })
        
        logger.debug("xcodeAccounts: \(xcodeAppleIDs)")
        logger.debug("accounts: \(accounts)")
        
        let newAccounts = Set(accountNames).subtracting(xcodeAccountNames)
        logger.info("newAccounts: \(newAccounts)")
        
        guard newAccounts.count > 0 else {
            logger.info("No new accounts to add into defaults")
            return
        }
        
        let newAccountRecords = newAccounts.map({ ["username": $0] as NSDictionary })
        let modifiedAppleIDs = (xcodeAppleIDs as NSArray).addingObjects(from: newAccountRecords)
        modifiedXcodeAppleIDLists[xcodeDefaultsIDEProductionSubkey] = modifiedAppleIDs
        
        xcodeDefaults.setValue(modifiedXcodeAppleIDLists.copy(), forKey: xcodeDefaultsAppleIDsKeys)

        // According to UserDefaults.synchronize documentation we have to use CFPreferencesAppSynchronize to sync in CLI
        CFPreferencesAppSynchronize(xcodeDefaultsIdentifier as CFString)
    }

    func importProfiles() throws {
        let provisionProfileNames = try FileManager.default.contentsOfDirectory(atPath: provisionProfilesFolderURL.path)
        let destinationDirectory = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/MobileDevice/Provisioning Profiles/")
        
        
        if !FileManager.default.fileExists(atPath: destinationDirectory.path) {
            try FileManager.default.createDirectory(atPath: destinationDirectory.path, withIntermediateDirectories: true)
        }
        
        for profileName in provisionProfileNames {
            // copy or replace
            _ = try FileManager.default.replaceItemAt(destinationDirectory.appendingPathComponent(profileName),
                                              withItemAt: provisionProfilesFolderURL.appendingPathComponent(profileName))
        }
    }
    
    deinit {
        do {
            try FileManager.default.removeItem(at: outputURL)
        } catch {
            logger.log(level: .error, "Failed to remove output folder at \(outputURL.path)")
        }
    }
}
