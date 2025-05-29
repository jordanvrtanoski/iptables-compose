#pragma once

#include <string>

namespace iptables {

class SystemUtils {
public:
    // System validation methods
    static bool isRunningAsRoot();
    static bool isIptablesAvailable();
    static bool canExecuteIptables();
    
    // System information
    static std::string getCurrentUser();
    static std::string getIptablesVersion();
    
    // Validation and error reporting
    static void validateSystemRequirements();
    static void printSystemInfo();
    
    // Command execution
    static std::string executeCommand(const std::string& command);
    
private:
    static bool commandExists(const std::string& command);
};

} // namespace iptables 