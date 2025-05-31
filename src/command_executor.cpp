#include "command_executor.hpp"
#include <iostream>
#include <sstream>
#include <cstdlib>
#include <array>
#include <memory>
#include <chrono>
#include <iomanip>

namespace iptables {

// Initialize static member
LogLevel CommandExecutor::current_log_level_ = LogLevel::Info;

CommandResult CommandExecutor::execute(const std::vector<std::string>& args) {
    if (args.empty()) {
        CommandResult result;
        result.success = false;
        result.exit_code = -1;
        result.stderr_output = "No command specified";
        result.command = "";
        return result;
    }
    
    std::string command = argsToCommand(args);
    return executeInternal(command);
}

CommandResult CommandExecutor::execute(const std::string& command) {
    // Log the command execution at INFO level for audit trails and debugging
    // This provides visibility into all iptables operations performed by the application
    log(LogLevel::Info, "Executing command: " + command);
    
    try {
        // Use popen() to execute the command and capture both stdout and stderr
        // The "2>&1" redirection combines stderr into stdout for unified output capture
        // This ensures we capture all command output regardless of which stream it uses
        std::unique_ptr<FILE, decltype(&pclose)> pipe(popen((command + " 2>&1").c_str(), "r"), pclose);
        
        if (!pipe) {
            // popen() failed - typically due to resource exhaustion or invalid command
            // This is a system-level failure rather than a command execution failure
            std::string error = "Failed to execute command: " + command;
            log(LogLevel::Error, error);
            
            CommandResult result;
            result.success = false;
            result.exit_code = 1;
            result.stderr_output = error;
            result.command = command;
            return result;
        }
        
        // Read command output in chunks using a fixed-size buffer
        // This approach handles arbitrary output sizes while controlling memory usage
        // The buffer size balances memory efficiency with read operation overhead
        std::array<char, 4096> buffer;
        std::string output;
        
        // Read all available output from the command
        // fgets() returns nullptr when EOF is reached or an error occurs
        while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
            output += buffer.data();
        }
        
        // Close the pipe and retrieve the command exit status
        // pclose() returns the exit status of the executed command
        // This status indicates whether the command succeeded or failed
        int exitStatus = pclose(pipe.release());
        
        // Extract the actual exit code from the pclose() return value
        // pclose() returns a status value that needs to be processed with WEXITSTATUS
        // On Unix systems, the exit status is encoded in the high byte
        int exitCode = WEXITSTATUS(exitStatus);
        
        // Log the command completion with exit status for debugging and auditing
        // Include timing information and output length for performance analysis
        std::string resultLog = "Command completed with exit code " + std::to_string(exitCode);
        if (!output.empty()) {
            resultLog += " (output: " + std::to_string(output.length()) + " bytes)";
        }
        log(exitCode == 0 ? LogLevel::Debug : LogLevel::Error, resultLog);
        
        // Return structured result with exit code and captured output
        // The caller can use CommandResult methods to check success and extract information
        CommandResult result;
        result.success = (exitCode == 0);
        result.exit_code = exitCode;
        result.stdout_output = output;
        result.stderr_output = "";
        result.command = command;
        return result;
        
    } catch (const std::exception& e) {
        // Handle any unexpected exceptions during command execution
        // This provides a consistent error handling interface for system failures
        std::string error = "Exception during command execution: " + std::string(e.what());
        log(LogLevel::Error, error);
        
        CommandResult result;
        result.success = false;
        result.exit_code = -1;
        result.stderr_output = error;
        result.command = command;
        return result;
    }
}

CommandResult CommandExecutor::executeIptables(const std::string& table, 
                                              const std::string& chain,
                                              const std::vector<std::string>& args) {
    std::vector<std::string> full_args = {"iptables", "-t", table};
    
    if (!chain.empty()) {
        // Add chain specification if provided
        for (const auto& arg : args) {
            if (arg == "-A" || arg == "-I" || arg == "-D" || arg == "-C" || arg == "-L") {
                full_args.push_back(arg);
                full_args.push_back(chain);
                break;
            }
        }
        
        // Add remaining arguments
        bool chain_added = false;
        for (const auto& arg : args) {
            if (arg == "-A" || arg == "-I" || arg == "-D" || arg == "-C" || arg == "-L") {
                if (!chain_added) {
                    full_args.push_back(arg);
                    full_args.push_back(chain);
                    chain_added = true;
                }
            } else {
                full_args.push_back(arg);
            }
        }
        
        if (!chain_added) {
            // If no chain operation specified, assume it's a generic command
            full_args.insert(full_args.end(), args.begin(), args.end());
        }
    } else {
        // No chain specified, add all arguments as-is
        full_args.insert(full_args.end(), args.begin(), args.end());
    }
    
    return execute(full_args);
}

CommandResult CommandExecutor::executeIptables(const std::vector<std::string>& args) {
    std::vector<std::string> full_args = {"iptables"};
    full_args.insert(full_args.end(), args.begin(), args.end());
    return execute(full_args);
}

CommandResult CommandExecutor::listRules(const std::string& table, const std::string& chain) {
    std::vector<std::string> args = {"-t", table, "-L"};
    
    if (!chain.empty()) {
        args.push_back(chain);
    }
    
    args.push_back("--line-numbers");
    args.push_back("-n"); // numeric output
    args.push_back("-v"); // verbose
    
    return executeIptables(args);
}

CommandResult CommandExecutor::removeRuleByLineNumber(const std::string& table,
                                                     const std::string& chain,
                                                     int line_number) {
    std::vector<std::string> args = {
        "-t", table,
        "-D", chain,
        std::to_string(line_number)
    };
    
    return executeIptables(args);
}

CommandResult CommandExecutor::setChainPolicy(const std::string& table,
                                             const std::string& chain,
                                             const std::string& policy) {
    std::vector<std::string> args = {
        "-t", table,
        "-P", chain,
        policy
    };
    
    return executeIptables(args);
}

CommandResult CommandExecutor::flushChain(const std::string& table, const std::string& chain) {
    std::vector<std::string> args = {"-t", table, "-F"};
    
    if (!chain.empty()) {
        args.push_back(chain);
    }
    
    return executeIptables(args);
}

void CommandExecutor::setLogLevel(LogLevel level) {
    // Update the global logging level for all CommandExecutor operations
    // This allows dynamic control of logging verbosity based on user preferences or debugging needs
    LogLevel oldLevel = current_log_level_;
    current_log_level_ = level;
    
    // Log the level change for audit purposes
    // This helps track when and why logging verbosity was modified
    std::string message = "Log level changed from " + logLevelToString(oldLevel) + 
                         " to " + logLevelToString(level);
    log(LogLevel::Info, message);
}

LogLevel CommandExecutor::getLogLevel() {
    return current_log_level_;
}

bool CommandExecutor::isIptablesAvailable() {
    // Check if iptables command is available in the system PATH
    // This is a basic availability check that doesn't verify permissions
    CommandResult result = execute("which iptables");
    return result.isSuccess();
}

CommandResult CommandExecutor::executeInternal(const std::string& command, bool capture_output) {
    CommandResult result;
    result.command = command;
    
    log(LogLevel::Debug, "Executing command: " + command);
    
    if (!capture_output) {
        // Simple execution without output capture
        int exit_code = std::system(command.c_str());
        result.exit_code = WEXITSTATUS(exit_code);
        result.success = (result.exit_code == 0);
        
        log(LogLevel::Debug, "Command completed with exit code: " + std::to_string(result.exit_code));
        return result;
    }
    
    // Execute command with output capture
    std::string stdout_cmd = command + " 2>/tmp/cmd_stderr_$$ && echo \"__EXIT_CODE_0__\" || echo \"__EXIT_CODE_$?__\"";
    
    std::array<char, 128> buffer;
    std::string stdout_result;
    
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(stdout_cmd.c_str(), "r"), pclose);
    if (!pipe) {
        result.success = false;
        result.exit_code = -1;
        result.stderr_output = "Failed to execute command";
        log(LogLevel::Error, "Failed to create pipe for command: " + command);
        return result;
    }
    
    // Read stdout
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        stdout_result += buffer.data();
    }
    
    // Extract exit code from stdout
    if (stdout_result.find("__EXIT_CODE_0__") != std::string::npos) {
        result.exit_code = 0;
        stdout_result = stdout_result.substr(0, stdout_result.find("__EXIT_CODE_0__"));
    } else if (stdout_result.find("__EXIT_CODE_") != std::string::npos) {
        size_t pos = stdout_result.find("__EXIT_CODE_") + 12;
        size_t end_pos = stdout_result.find("__", pos);
        if (end_pos != std::string::npos) {
            std::string exit_code_str = stdout_result.substr(pos, end_pos - pos);
            try {
                result.exit_code = std::stoi(exit_code_str);
            } catch (...) {
                result.exit_code = -1;
            }
        }
        stdout_result = stdout_result.substr(0, stdout_result.find("__EXIT_CODE_"));
    }
    
    result.stdout_output = stdout_result;
    
    // Read stderr from temporary file
    std::string stderr_cmd = "cat /tmp/cmd_stderr_$$ 2>/dev/null && rm -f /tmp/cmd_stderr_$$";
    std::unique_ptr<FILE, decltype(&pclose)> stderr_pipe(popen(stderr_cmd.c_str(), "r"), pclose);
    if (stderr_pipe) {
        std::string stderr_result;
        while (fgets(buffer.data(), buffer.size(), stderr_pipe.get()) != nullptr) {
            stderr_result += buffer.data();
        }
        result.stderr_output = stderr_result;
    }
    
    result.success = (result.exit_code == 0);
    
    // Remove trailing newlines
    if (!result.stdout_output.empty() && result.stdout_output.back() == '\n') {
        result.stdout_output.pop_back();
    }
    if (!result.stderr_output.empty() && result.stderr_output.back() == '\n') {
        result.stderr_output.pop_back();
    }
    
    if (result.success) {
        log(LogLevel::Debug, "Command completed successfully");
        if (!result.stdout_output.empty()) {
            log(LogLevel::Debug, "Stdout: " + result.stdout_output);
        }
    } else {
        log(LogLevel::Error, "Command failed with exit code: " + std::to_string(result.exit_code));
        if (!result.stderr_output.empty()) {
            log(LogLevel::Error, "Stderr: " + result.stderr_output);
        }
    }
    
    return result;
}

void CommandExecutor::log(LogLevel level, const std::string& message) {
    if (level > current_log_level_) {
        return;
    }
    
    // Get current timestamp
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    
    std::ostringstream timestamp;
    timestamp << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    timestamp << '.' << std::setfill('0') << std::setw(3) << ms.count();
    
    // Level prefix
    std::string level_str;
    std::ostream* output_stream = &std::cout;
    
    switch (level) {
        case LogLevel::Error:
            level_str = "ERROR";
            output_stream = &std::cerr;
            break;
        case LogLevel::Warning:
            level_str = "WARN ";
            output_stream = &std::cerr;
            break;
        case LogLevel::Info:
            level_str = "INFO ";
            break;
        case LogLevel::Debug:
            level_str = "DEBUG";
            break;
        case LogLevel::None:
            return; // Don't log anything
    }
    
    *output_stream << "[" << timestamp.str() << "] [" << level_str << "] CommandExecutor: " 
                   << message << std::endl;
}

std::string CommandExecutor::argsToCommand(const std::vector<std::string>& args) {
    if (args.empty()) {
        return "";
    }
    
    std::ostringstream command;
    for (size_t i = 0; i < args.size(); ++i) {
        if (i > 0) {
            command << " ";
        }
        command << escapeShellArg(args[i]);
    }
    
    return command.str();
}

std::string CommandExecutor::escapeShellArg(const std::string& arg) {
    // If argument contains no special characters, return as-is
    if (arg.find_first_of(" \t\n\r\"'\\$`|&;<>(){}[]?*~") == std::string::npos) {
        return arg;
    }
    
    // Escape argument with single quotes
    std::string escaped = "'";
    for (char c : arg) {
        if (c == '\'') {
            escaped += "'\"'\"'";  // End quote, escaped single quote, start quote
        } else {
            escaped += c;
        }
    }
    escaped += "'";
    
    return escaped;
}

std::string CommandExecutor::logLevelToString(LogLevel level) {
    // Convert LogLevel enum to human-readable string representation
    // This provides consistent formatting for log output across the application
    switch (level) {
        case LogLevel::Error:
            return "ERROR";   // Critical errors that prevent operation completion
        case LogLevel::Warning:
            return "WARNING"; // Non-fatal issues that may affect functionality
        case LogLevel::Info:
            return "INFO";    // General informational messages about operations
        case LogLevel::Debug:
            return "DEBUG";   // Detailed debugging information for troubleshooting
        case LogLevel::None:
            return "NONE";    // No logging
        default:
            return "UNKNOWN"; // Fallback for invalid enum values
    }
}

} // namespace iptables 