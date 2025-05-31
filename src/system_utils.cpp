#include "system_utils.hpp"
#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <cstring>
#include <stdexcept>
#include <array>
#include <memory>
#include <vector>
#include <sstream>
#include <filesystem>

namespace iptables {

bool SystemUtils::isRunningAsRoot() {
    // Check effective user ID (EUID) rather than real user ID (RUID)
    // EUID determines actual privileges, while RUID indicates the original user
    // This handles cases where the program is run with sudo or has setuid bit set
    // getuid() returns the real user ID, geteuid() returns the effective user ID
    uid_t euid = geteuid();
    
    // Root user always has UID 0 in Unix-like systems
    // This is a fundamental security boundary in Unix permissions model
    return euid == 0;
}

bool SystemUtils::isIptablesAvailable() {
    // Use the system() call to check if iptables command exists and is executable
    // The 'command -v' shell builtin is POSIX compliant and more reliable than 'which'
    // It returns 0 if the command is found, non-zero otherwise
    // /dev/null redirection prevents output from cluttering the terminal
    // This approach works across different shell environments and distributions
    int result = system("command -v iptables > /dev/null 2>&1");
    
    // system() returns the exit status of the executed command
    // WEXITSTATUS() macro extracts the actual exit code from the return value
    // Exit code 0 indicates success (command found), non-zero indicates failure
    return result == 0;
}

bool SystemUtils::canExecuteIptables() {
    if (!isIptablesAvailable()) {
        return false;
    }
    
    // Try to execute a simple iptables command to check permissions
    std::string output = executeCommand("iptables --version 2>/dev/null");
    return !output.empty();
}

std::string SystemUtils::getCurrentUser() {
    uid_t uid = getuid();
    struct passwd* pw = getpwuid(uid);
    if (pw) {
        return std::string(pw->pw_name);
    }
    return "unknown";
}

std::string SystemUtils::getIptablesVersion() {
    if (!isIptablesAvailable()) {
        return "not available";
    }
    
    std::string version = executeCommand("iptables --version 2>/dev/null");
    if (version.empty()) {
        return "unknown";
    }
    
    // Remove trailing newline
    if (!version.empty() && version.back() == '\n') {
        version.pop_back();
    }
    
    return version;
}

std::vector<std::string> SystemUtils::validateSystemRequirements() {
    std::vector<std::string> errors;
    
    // Check for root privileges first as this is fundamental for iptables operations
    // iptables requires CAP_NET_ADMIN capability, which is typically only available to root
    // Running without root will cause all iptables operations to fail with permission denied
    if (!isRunningAsRoot()) {
        errors.push_back("This application requires root privileges to modify iptables rules");
        errors.push_back("Debug: Current effective UID is " + std::to_string(geteuid()) + 
                       " (root UID is 0)");
        errors.push_back("Debug: Try running with 'sudo' or as root user");
    }
    
    // Verify that iptables command is available in the system PATH
    // This ensures that the CommandExecutor will be able to execute iptables commands
    // Missing iptables typically indicates an incomplete system installation
    if (!isIptablesAvailable()) {
        errors.push_back("iptables command not found in system PATH");
        errors.push_back("Debug: iptables package may not be installed");
        errors.push_back("Debug: Install with 'apt install iptables' (Ubuntu/Debian) or 'yum install iptables' (CentOS/RHEL)");
        
        // Show current PATH for troubleshooting PATH-related issues
        const char* path = std::getenv("PATH");
        if (path) {
            errors.push_back("Debug: Current PATH: " + std::string(path));
        }
    }
    
    // Additional system checks could be added here:
    // - Kernel module availability (ip_tables, iptable_filter, etc.)
    // - Sufficient disk space for logging
    // - Network namespace compatibility
    // - SELinux/AppArmor policy checks
    
    return errors;
}

void SystemUtils::printSystemInfo() {
    // Display comprehensive system information for debugging and verification
    std::cout << "System Information:\n";
    std::cout << "==================\n";
    
    // Show current user context - both real and effective user information
    // This is crucial for understanding privilege escalation and security context
    uid_t ruid = getuid();   // Real user ID - the original user who started the process
    uid_t euid = geteuid();  // Effective user ID - the user ID used for permission checks
    
    std::cout << "Real User ID: " << ruid;
    
    // Resolve real user ID to username for better readability
    // getpwuid() may return nullptr if the user doesn't exist in /etc/passwd
    struct passwd* real_user = getpwuid(ruid);
    if (real_user != nullptr) {
        std::cout << " (" << real_user->pw_name << ")";
    }
    std::cout << "\n";
    
    std::cout << "Effective User ID: " << euid;
    
    // Resolve effective user ID to username
    // This shows the actual user context for permission checks
    struct passwd* eff_user = getpwuid(euid);
    if (eff_user != nullptr) {
        std::cout << " (" << eff_user->pw_name << ")";
    }
    std::cout << "\n";
    
    // Indicate privilege status clearly for user understanding
    // This helps users verify they have the necessary permissions
    std::cout << "Running as root: " << (isRunningAsRoot() ? "Yes" : "No") << "\n";
    
    // Check and display iptables availability status
    // This verifies that the core dependency is available for execution
    std::cout << "iptables available: " << (isIptablesAvailable() ? "Yes" : "No") << "\n";
    
    // Display current working directory for context
    // This helps with relative path resolution and file access debugging
    try {
        std::filesystem::path cwd = std::filesystem::current_path();
        std::cout << "Working directory: " << cwd.string() << "\n";
    } catch (const std::filesystem::filesystem_error& e) {
        // Handle cases where current directory is inaccessible or deleted
        std::cout << "Working directory: <unable to determine>\n";
    }
    
    // Show environment variables that affect application behavior
    // PATH affects command resolution, HOME affects file location defaults
    const char* path = std::getenv("PATH");
    if (path) {
        std::cout << "PATH: " << path << "\n";
    }
    
    const char* home = std::getenv("HOME");
    if (home) {
        std::cout << "HOME: " << home << "\n";
    }
    
    // Additional system information that could be useful:
    // - Linux distribution and version
    // - Kernel version (affects iptables feature availability)
    // - Available iptables modules
    // - Current iptables rule count
    // - System memory and disk space
    
    std::cout << "\n";
}

bool SystemUtils::commandExists(const std::string& command) {
    std::string check_cmd = "which " + command + " >/dev/null 2>&1";
    return system(check_cmd.c_str()) == 0;
}

std::string SystemUtils::executeCommand(const std::string& command) {
    std::array<char, 128> buffer;
    std::string result;
    
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"), pclose);
    if (!pipe) {
        return "";
    }
    
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    
    return result;
}

} // namespace iptables 