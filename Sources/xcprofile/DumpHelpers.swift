import Security
import Foundation

func dumpACLs(for key: SecKeychainItem) {
    var access: SecAccess!
    SecKeychainItemCopyAccess(key, &access)
    
    dumpSecAccess(access)
}

func dumpSecAccess(_ secAccess: SecAccess) {
    var aclListRaw: CFArray!
    SecAccessCopyACLList(secAccess, &aclListRaw)
    
    let aclList = aclListRaw as! [SecACL]
    for (index, acl) in aclList.enumerated() {
        dumpACL(acl, index: index)
    }
    
    print(#function, "completed")
}

func dumpACL(_ acl: SecACL, index: Int = 0) {
    let authorizations = SecACLCopyAuthorizations(acl) as NSArray
    
    var applicationsRaw: CFArray!
    var description: CFString!
    var promptSelector: SecKeychainPromptSelector = .init(rawValue: 666)
    SecACLCopyContents(acl, &applicationsRaw, &description, &promptSelector)
    
    print("ACL #\(index + 1), description: \(description!)")
    print("Authorizations:")
    for (authIndex, authorization) in (authorizations as! [String]).enumerated() {
        print("\t[\(authIndex)] = \(authorization)")
    }
    if let applications = applicationsRaw as? [SecTrustedApplication] {
        print("Applications[count=\(applications.count)]:")
        for (appIndex, app) in (applications).enumerated() {
            var applicationPathData: CFData!
            SecTrustedApplicationCopyData(app, &applicationPathData)
            let applicationPath = String(data: applicationPathData as Data, encoding: .utf8)!
            
            print("\t[\(appIndex)] = \(app)")
            print("\t\t\(applicationPath)")
        }
    } else {
        print("Applications: nil")
    }
    print("PromptSelector: \(promptSelector)")
    print("")
}

