import Foundation
import ArgumentParser

struct ValidateCommand: ParsableCommand {
    @Argument(help: "Absolute path to .developerprofile")
    var profilePath: String
    
    @Option(name: .shortAndLong, help: "Password to decrypt .developerprofile")
    var password: String
    
    static var configuration = CommandConfiguration(commandName: "validate")
    
    func run() throws {
        let profileURL = URL(fileURLWithPath: profilePath)
        let profile = try DeveloperEncryptedProfile(url: profileURL).decompress(password: password)
        
        guard try profile.validateTokens() else {
            throw ExitCode.validationFailure
        }
        
        logger.info("Validation passed successfully")
    }
}
