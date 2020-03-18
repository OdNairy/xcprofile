import ArgumentParser
import Logging

LoggingSystem.bootstrap(StreamLogHandler.standardOutput)
var logger = Logger(label: "com.gardukevich.xcprofile")
#if DEBUG
logger.logLevel = .trace
#endif

struct EntryCommand: ParsableCommand {
    static var configuration = CommandConfiguration(subcommands: [ImportCommand.self, ReExportCommand.self],
                                                    defaultSubcommand: ImportCommand.self)
}

EntryCommand.main()
