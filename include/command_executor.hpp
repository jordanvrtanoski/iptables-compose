/**
 * @file command_executor.hpp
 * @brief Command execution engine for iptables-compose-cpp
 * @author iptables-compose-cpp Development Team
 * @date 2024
 * 
 * This file contains the CommandExecutor class which provides a robust interface
 * for executing system commands, particularly iptables operations. It includes
 * comprehensive error handling, logging, output capture, and specialized methods
 * for common iptables operations.
 */

#pragma once

#include <string>
#include <vector>
#include <optional>

namespace iptables {

/**
 * @struct CommandResult
 * @brief Structure representing the result of a command execution
 * 
 * Contains comprehensive information about command execution including
 * exit status, output streams, and helper methods for result analysis.
 * Used by all CommandExecutor methods to provide detailed execution feedback.
 */
struct CommandResult {
    bool success = false;           ///< Whether the command executed without errors
    int exit_code = -1;            ///< Process exit code (0 = success)
    std::string stdout_output;     ///< Standard output from the command
    std::string stderr_output;     ///< Standard error output from the command
    std::string command;           ///< The actual command that was executed
    
    /**
     * @brief Check if the command executed successfully
     * @return true if exit code is 0 and success flag is true
     * 
     * Convenience method that checks both the success flag and exit code
     * to determine if the command completed successfully.
     */
    bool isSuccess() const {
        return success && exit_code == 0;
    }
    
    /**
     * @brief Get combined output (stdout + stderr)
     * @return Combined output string with newline separation
     * 
     * Merges stdout and stderr into a single string for cases where
     * the distinction is not important. Adds newline between streams
     * if both contain content.
     */
    std::string getCombinedOutput() const {
        std::string combined = stdout_output;
        if (!stderr_output.empty()) {
            if (!combined.empty()) combined += "\n";
            combined += stderr_output;
        }
        return combined;
    }
    
    /**
     * @brief Get error message if command failed
     * @return Error message string or empty string if successful
     * 
     * Generates a comprehensive error message including the command,
     * exit code, and stderr output when the command fails. Returns
     * empty string for successful commands.
     */
    std::string getErrorMessage() const {
        if (isSuccess()) {
            return "";
        }
        
        std::string error = "Command failed: " + command;
        error += " (exit code: " + std::to_string(exit_code) + ")";
        
        if (!stderr_output.empty()) {
            error += "\nError output: " + stderr_output;
        }
        
        return error;
    }
};

/**
 * @enum LogLevel
 * @brief Logging levels for command execution
 * 
 * Controls the verbosity of command execution logging:
 * - None: No logging output
 * - Error: Only error messages
 * - Warning: Errors and warnings
 * - Info: Errors, warnings, and informational messages
 * - Debug: All messages including detailed execution information
 */
enum class LogLevel {
    None,    ///< No logging
    Error,   ///< Error messages only
    Warning, ///< Error and warning messages
    Info,    ///< Informational messages and above
    Debug    ///< All messages including debug information
};

/**
 * @class CommandExecutor
 * @brief Enhanced command executor with structured results and logging
 * 
 * The CommandExecutor class provides a comprehensive interface for executing
 * system commands with emphasis on iptables operations. It offers:
 * 
 * - Structured command results with detailed information
 * - Configurable logging levels for debugging and monitoring
 * - Specialized methods for common iptables operations
 * - Robust error handling and output capture
 * - Shell argument escaping for security
 * - Command validation and availability checking
 * 
 * All methods are static, making the class a utility interface that can be
 * used throughout the application without instantiation.
 */
class CommandExecutor {
public:
    /**
     * @brief Execute a generic command with argument vector
     * @param args Command arguments (first is the command, rest are arguments)
     * @return CommandResult with comprehensive execution details
     * @throws std::invalid_argument if args vector is empty
     * 
     * Executes a command specified as a vector of arguments. The first element
     * should be the command name, and subsequent elements are arguments.
     * This is the preferred method for command execution as it handles
     * argument escaping automatically.
     */
    static CommandResult execute(const std::vector<std::string>& args);
    
    /**
     * @brief Execute a command from a single string
     * @param command Full command string to execute
     * @return CommandResult with comprehensive execution details
     * @throws std::invalid_argument if command string is empty
     * 
     * Executes a command specified as a single string. The string is passed
     * directly to the shell, so shell features like pipes and redirection
     * are available but manual escaping may be required.
     */
    static CommandResult execute(const std::string& command);
    
    /**
     * @brief Execute an iptables command with specific table and chain
     * @param table Iptables table (filter, nat, mangle, raw)
     * @param chain Chain name (INPUT, OUTPUT, FORWARD, PREROUTING, POSTROUTING)
     * @param args Additional iptables arguments (without table/chain specification)
     * @return CommandResult with execution details
     * @throws std::invalid_argument if table or chain is invalid
     * 
     * Specialized method for iptables commands that automatically handles
     * table and chain specification. Validates table and chain names before
     * execution to prevent invalid commands.
     */
    static CommandResult executeIptables(const std::string& table, 
                                       const std::string& chain,
                                       const std::vector<std::string>& args);
    
    /**
     * @brief Execute a simple iptables command
     * @param args Iptables arguments (without 'iptables' command prefix)
     * @return CommandResult with execution details
     * 
     * Convenience method for iptables commands that automatically prepends
     * the 'iptables' command. Arguments should not include the command itself.
     */
    static CommandResult executeIptables(const std::vector<std::string>& args);
    
    /**
     * @brief List rules from specified table and chain with line numbers
     * @param table Iptables table name (default: "filter")
     * @param chain Chain name (empty for all chains in table)
     * @return CommandResult with rule listing in stdout_output
     * 
     * Lists iptables rules using the --line-numbers option for rule
     * identification. Output includes rule numbers that can be used
     * with removeRuleByLineNumber(). If chain is empty, lists all
     * chains in the specified table.
     */
    static CommandResult listRules(const std::string& table = "filter", 
                                 const std::string& chain = "");
    
    /**
     * @brief Remove rule by line number
     * @param table Iptables table name
     * @param chain Chain name
     * @param line_number Line number to remove (1-based indexing)
     * @return CommandResult with removal status
     * @throws std::invalid_argument if line_number is less than 1
     * 
     * Removes a specific rule by its line number as shown by listRules().
     * Line numbers are 1-based and should be obtained from recent rule
     * listings as they change when rules are added or removed.
     */
    static CommandResult removeRuleByLineNumber(const std::string& table,
                                              const std::string& chain,
                                              int line_number);
    
    /**
     * @brief Set chain policy
     * @param table Iptables table name
     * @param chain Chain name (INPUT, OUTPUT, FORWARD)
     * @param policy Policy action (ACCEPT, DROP, REJECT)
     * @return CommandResult with policy setting status
     * @throws std::invalid_argument if policy is invalid
     * 
     * Sets the default policy for a chain. Only built-in chains support
     * policies. The policy determines what happens to packets that don't
     * match any rules in the chain.
     */
    static CommandResult setChainPolicy(const std::string& table,
                                      const std::string& chain,
                                      const std::string& policy);
    
    /**
     * @brief Flush all rules from a chain
     * @param table Iptables table name (default: "filter")
     * @param chain Chain name (empty for all chains in table)
     * @return CommandResult with flush status
     * 
     * Removes all rules from the specified chain. If chain is empty,
     * flushes all chains in the specified table. This operation cannot
     * be undone, so use with caution.
     */
    static CommandResult flushChain(const std::string& table = "filter",
                                  const std::string& chain = "");
    
    /**
     * @brief Enable or disable logging
     * @param level Logging level to set
     * 
     * Sets the global logging level for all CommandExecutor operations.
     * Higher levels include all lower level messages. Debug level
     * provides detailed information about command execution.
     */
    static void setLogLevel(LogLevel level);
    
    /**
     * @brief Get current logging level
     * @return Current logging level
     */
    static LogLevel getLogLevel();
    
    /**
     * @brief Check if iptables command is available
     * @return true if iptables is available and executable
     * 
     * Verifies that the iptables command exists in the system PATH
     * and can be executed. This is a basic availability check that
     * doesn't verify permissions or functionality.
     */
    static bool isIptablesAvailable();
    
private:
    /**
     * @brief Internal method to execute command with full control
     * @param command Command string to execute
     * @param capture_output Whether to capture stdout/stderr
     * @return CommandResult with execution details
     * 
     * Core execution method used by all public methods. Handles process
     * creation, output capture, error handling, and result structure
     * population. Uses popen() for command execution.
     */
    static CommandResult executeInternal(const std::string& command, bool capture_output = true);
    
    /**
     * @brief Log a message at the specified level
     * @param level Log level for the message
     * @param message Message content to log
     * 
     * Internal logging method that respects the current log level setting.
     * Messages are written to stderr with timestamp and level information.
     */
    static void log(LogLevel level, const std::string& message);
    
    /**
     * @brief Convert vector of arguments to command string
     * @param args Command arguments vector
     * @return Properly escaped command string
     * 
     * Converts a vector of command arguments into a single command string
     * with proper shell escaping. Used internally to prepare commands
     * for execution.
     */
    static std::string argsToCommand(const std::vector<std::string>& args);
    
    /**
     * @brief Escape shell argument for safe execution
     * @param arg Argument string to escape
     * @return Escaped argument safe for shell execution
     * 
     * Escapes special characters in command arguments to prevent shell
     * injection and ensure arguments are interpreted literally. Uses
     * single quotes with proper escape handling.
     */
    static std::string escapeShellArg(const std::string& arg);
    
    /**
     * @brief Convert LogLevel enum to string representation
     * @param level LogLevel enum value
     * @return String representation of the log level
     * 
     * Converts LogLevel enum values to human-readable strings for
     * logging output formatting.
     */
    static std::string logLevelToString(LogLevel level);
    
    static LogLevel current_log_level_; ///< Current global logging level
};

} // namespace iptables 