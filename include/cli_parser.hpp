#pragma once

#include <filesystem>
#include <optional>
#include <string>

namespace iptables {

class CLIParser {
public:
    struct Options {
        std::optional<std::filesystem::path> config_file;
        bool reset = false;
        bool remove_rules = false;
        bool show_license = false;
        bool help = false;
        bool debug = false;  // Bypass system validation for testing
    };
    
    static Options parse(int argc, char* argv[]);
    static void printUsage(const std::string& program_name);
    static void printLicense();
    
private:
    static void validateOptions(const Options& options);
};

} // namespace iptables 