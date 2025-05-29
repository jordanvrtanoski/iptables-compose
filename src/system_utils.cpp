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

namespace iptables {

bool SystemUtils::isRunningAsRoot() {
    return geteuid() == 0;
}

bool SystemUtils::isIptablesAvailable() {
    return commandExists("iptables");
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

void SystemUtils::validateSystemRequirements() {
    std::vector<std::string> errors;
    
    // Check if iptables is available
    if (!isIptablesAvailable()) {
        errors.push_back("iptables command not found in PATH");
    }
    
    // Check if running as root
    if (!isRunningAsRoot()) {
        errors.push_back("This application requires root privileges to modify iptables rules");
    }
    
    // Check if iptables can be executed
    if (isIptablesAvailable() && !canExecuteIptables()) {
        errors.push_back("Cannot execute iptables commands (permission denied or iptables not functional)");
    }
    
    if (!errors.empty()) {
        std::cerr << "System validation failed:\n";
        for (const auto& error : errors) {
            std::cerr << "  - " << error << "\n";
        }
        std::cerr << "\nPlease ensure:\n";
        std::cerr << "  1. iptables is installed and available in PATH\n";
        std::cerr << "  2. You are running this application as root (use sudo)\n";
        std::cerr << "  3. iptables kernel modules are loaded\n";
        throw std::runtime_error("System requirements not met");
    }
}

void SystemUtils::printSystemInfo() {
    std::cout << "System Information:\n";
    std::cout << "  User: " << getCurrentUser();
    if (isRunningAsRoot()) {
        std::cout << " (root)";
    }
    std::cout << "\n";
    std::cout << "  iptables: " << getIptablesVersion() << "\n";
    std::cout << "  iptables available: " << (isIptablesAvailable() ? "yes" : "no") << "\n";
    std::cout << "  Can execute iptables: " << (canExecuteIptables() ? "yes" : "no") << "\n";
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