/**
 * @file system_utils.hpp
 * @brief System utilities and validation for iptables-compose-cpp
 * @author iptables-compose-cpp Development Team
 * @date 2024
 * 
 * This file contains the SystemUtils class responsible for system validation,
 * environment checking, and basic command execution utilities required for
 * iptables operations.
 */

#pragma once

#include <string>
#include <vector>

namespace iptables {

/**
 * @class SystemUtils
 * @brief System utilities and validation helper class
 * 
 * The SystemUtils class provides static methods for validating system requirements,
 * checking user privileges, verifying iptables availability, and executing basic
 * system commands. All iptables operations require root privileges and iptables
 * to be installed and accessible.
 */
class SystemUtils {
public:
    /**
     * @brief Check if the current process is running with root privileges
     * @return true if running as root, false otherwise
     * 
     * Uses getuid() to check if the effective user ID is 0 (root).
     * Required for iptables operations which need administrative privileges.
     */
    static bool isRunningAsRoot();
    
    /**
     * @brief Check if iptables command is available in the system
     * @return true if iptables is available, false otherwise
     * 
     * Verifies that the iptables binary exists and is executable in the system PATH.
     * This is a prerequisite for all firewall operations.
     */
    static bool isIptablesAvailable();
    
    /**
     * @brief Test if iptables can be executed with current privileges
     * @return true if iptables can be executed, false otherwise
     * 
     * Attempts to execute a simple iptables command to verify both availability
     * and execution permissions. More comprehensive than isIptablesAvailable().
     */
    static bool canExecuteIptables();
    
    /**
     * @brief Get the name of the current system user
     * @return String containing the current username
     * 
     * Retrieves the username associated with the current process.
     * Useful for logging and system information display.
     */
    static std::string getCurrentUser();
    
    /**
     * @brief Get the version of the installed iptables
     * @return String containing iptables version information
     * 
     * Executes 'iptables --version' to retrieve version information.
     * Returns empty string if iptables is not available or executable.
     */
    static std::string getIptablesVersion();
    
    /**
     * @brief Validate all system requirements for iptables operations
     * @return Vector of error messages, empty if all requirements are met
     * 
     * Performs comprehensive validation including root privileges,
     * iptables availability, and execution permissions. Returns detailed
     * error messages if requirements are not satisfied.
     */
    static std::vector<std::string> validateSystemRequirements();
    
    /**
     * @brief Print comprehensive system information to stdout
     * 
     * Displays current user, privilege status, iptables availability,
     * version information, and other relevant system details.
     * Useful for debugging and system verification.
     */
    static void printSystemInfo();
    
    /**
     * @brief Execute a system command and return its output
     * @param command The command string to execute
     * @return String containing the command's stdout output
     * @throws std::runtime_error if command execution fails
     * 
     * Executes the specified command using popen() and captures its output.
     * This is a basic command execution utility for simple operations.
     */
    static std::string executeCommand(const std::string& command);
    
private:
    /**
     * @brief Check if a command exists in the system PATH
     * @param command Name of the command to check
     * @return true if command exists and is executable, false otherwise
     * 
     * Internal utility method used by other validation functions to check
     * command availability in the system PATH.
     */
    static bool commandExists(const std::string& command);
};

} // namespace iptables 