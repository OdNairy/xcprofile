import ArgumentParser
import Logging

let logger = Logger(label: "com.gardukevich.xcprofile")

struct EntryCommand: ParsableCommand {
    static var configuration = CommandConfiguration(subcommands: [ImportCommand.self, ReExportCommand.self],
                                                    defaultSubcommand: ImportCommand.self)
}

EntryCommand.main()
