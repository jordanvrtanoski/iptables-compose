#pragma once

#include <string>
#include <vector>
#include <optional>

namespace iptables {

/**
 * @brief Structure representing the result of a command execution
 */
struct CommandResult {
    bool success = false;
    int exit_code = -1;
    std::string stdout_output;
    std::string stderr_output;
    std::string command;
    
    /**
     * @brief Check if the command executed successfully
     * @return true if exit code is 0 and success flag is true
     */
    bool isSuccess() const {
        return success && exit_code == 0;
    }
    
    /**
     * @brief Get combined output (stdout + stderr)
     * @return Combined output string
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
     * @return Error message or empty string if successful
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
 * @brief Logging levels for command execution
 */
enum class LogLevel {
    None,
    Error,
    Warning,
    Info,
    Debug
};

/**
 * @brief Enhanced command executor with structured results and logging
 */
class CommandExecutor {
public:
    /**
     * @brief Execute a generic command
     * @param args Command arguments (first is the command, rest are arguments)
     * @return CommandResult with execution details
     */
    static CommandResult execute(const std::vector<std::string>& args);
    
    /**
     * @brief Execute a command from a single string
     * @param command Full command string
     * @return CommandResult with execution details
     */
    static CommandResult execute(const std::string& command);
    
    /**
     * @brief Execute an iptables command with specific table support
     * @param table Iptables table (filter, nat, mangle, raw)
     * @param chain Chain name (INPUT, OUTPUT, FORWARD, PREROUTING, POSTROUTING)
     * @param args Additional iptables arguments
     * @return CommandResult with execution details
     */
    static CommandResult executeIptables(const std::string& table, 
                                       const std::string& chain,
                                       const std::vector<std::string>& args);
    
    /**
     * @brief Execute a simple iptables command
     * @param args Iptables arguments (without 'iptables' command)
     * @return CommandResult with execution details
     */
    static CommandResult executeIptables(const std::vector<std::string>& args);
    
    /**
     * @brief List rules from specified table and chain with line numbers
     * @param table Iptables table name
     * @param chain Chain name
     * @return CommandResult with rule listing
     */
    static CommandResult listRules(const std::string& table = "filter", 
                                 const std::string& chain = "");
    
    /**
     * @brief Remove rule by line number
     * @param table Iptables table name
     * @param chain Chain name
     * @param line_number Line number to remove
     * @return CommandResult with removal status
     */
    static CommandResult removeRuleByLineNumber(const std::string& table,
                                              const std::string& chain,
                                              int line_number);
    
    /**
     * @brief Set chain policy
     * @param table Iptables table name
     * @param chain Chain name
     * @param policy Policy (ACCEPT, DROP, REJECT)
     * @return CommandResult with policy setting status
     */
    static CommandResult setChainPolicy(const std::string& table,
                                      const std::string& chain,
                                      const std::string& policy);
    
    /**
     * @brief Flush all rules from a chain
     * @param table Iptables table name
     * @param chain Chain name (empty for all chains)
     * @return CommandResult with flush status
     */
    static CommandResult flushChain(const std::string& table = "filter",
                                  const std::string& chain = "");
    
    /**
     * @brief Enable or disable logging
     * @param level Logging level to set
     */
    static void setLogLevel(LogLevel level);
    
    /**
     * @brief Get current logging level
     * @return Current logging level
     */
    static LogLevel getLogLevel();
    
    /**
     * @brief Check if iptables command is available
     * @return true if iptables is available
     */
    static bool isIptablesAvailable();
    
private:
    /**
     * @brief Internal method to execute command with full control
     * @param command Command to execute
     * @param capture_output Whether to capture stdout/stderr
     * @return CommandResult with execution details
     */
    static CommandResult executeInternal(const std::string& command, bool capture_output = true);
    
    /**
     * @brief Log a message at the specified level
     * @param level Log level
     * @param message Message to log
     */
    static void log(LogLevel level, const std::string& message);
    
    /**
     * @brief Convert vector of arguments to command string
     * @param args Command arguments
     * @return Command string
     */
    static std::string argsToCommand(const std::vector<std::string>& args);
    
    /**
     * @brief Escape shell argument
     * @param arg Argument to escape
     * @return Escaped argument
     */
    static std::string escapeShellArg(const std::string& arg);
    
    static LogLevel current_log_level_;
};

} // namespace iptables 