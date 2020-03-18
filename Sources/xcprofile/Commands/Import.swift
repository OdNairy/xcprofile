import Foundation
import ArgumentParser

struct ImportCommand: ParsableCommand {
    @Option(name: .shortAndLong, help: "Password to decrypt .developerprofile")
    var password: String
    
    @Argument(help: "Absolute path to .developerprofile")
    var profilePath: String
    
    func run() throws {
        let profileURL = URL(fileURLWithTildePath: profilePath)
        logger.trace("ProfileURL: \(profileURL.path)", metadata: ["input path":.string(profilePath)])
        
        guard profileURL.lastPathComponent.contains(".developerprofile") else {
            throw ExitCode.failure
        }
        
        let encryptedProfile = DeveloperEncryptedProfile(url: profileURL)
        let profile = try encryptedProfile.decompress(password: password)
        logger.trace("Decrypted profile at \(profile.outputURL.path)")
        
        try profile.import()
    }
    
    static var configuration = CommandConfiguration(commandName: "import")
}
