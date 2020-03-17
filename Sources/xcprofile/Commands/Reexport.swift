import Foundation
import ArgumentParser

struct ReExportCommand: ParsableCommand {
    @Argument(help: "Absolute path to .developerprofile")
    var profilePath: String
    
    @Option(name: .shortAndLong, help: "Password to decrypt .developerprofile")
    var password: String
    
    static var configuration = CommandConfiguration(commandName: "reexport")
    
    func run() throws {
        let profileURL = URL(fileURLWithPath: profilePath)
        let profile = try DeveloperEncryptedProfile(url: profileURL).decompress(password: password)
        
        try profile.reexportKeychain()
        let reexportedProfile = try profile.compress(password: password)
        
        logger.info("Reexport passed successfully. Path: \(reexportedProfile.inputURL.path)")
    }
}
