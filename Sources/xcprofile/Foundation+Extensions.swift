import Foundation

extension URL {
    /// Initializes a newly created file URL referencing the local file or directory at path.
    /// Automatically expans tilde in path. Supported formats: `~` and `~anotherUser`
    ///
    /// If an empty string is used for the path, then the path is assumed to be ".".
    init(fileURLWithTildePath tildePath: String) {
        let path = (tildePath as NSString).expandingTildeInPath
        self.init(fileURLWithPath: path)
    }
}
