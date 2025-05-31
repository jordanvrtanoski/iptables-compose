#include "cli_parser.hpp"
#include <iostream>
#include <fstream>
#include <stdexcept>
#include <vector>
#include <getopt.h>

namespace iptables {

CLIParser::Options CLIParser::parse(int argc, char* argv[]) {
    Options options;
    
    // Define long options structure for getopt_long
    // This enables both short (-r) and long (--reset) option formats
    // The structure specifies option names, argument requirements, and short option mappings
    static struct option long_options[] = {
        {"reset",        no_argument,       0, 'r'},  // Reset iptables before applying config
        {"remove-rules", no_argument,       0, 'm'},  // Remove YAML-managed rules only
        {"license",      no_argument,       0, 'l'},  // Display license information
        {"help",         no_argument,       0, 'h'},  // Show usage help
        {"debug",        no_argument,       0, 'd'},  // Debug mode for testing without root
        {0, 0, 0, 0}  // Terminator entry required by getopt_long
    };
    
    int option_index = 0;  // Index into long_options array (set by getopt_long)
    int c;                 // Current option character returned by getopt_long
    
    // Parse options using getopt_long for robust argument handling
    // The option string "rmlhd" specifies valid short options (all take no arguments)
    // getopt_long handles option bundling (-rh), long options (--reset), and error detection
    while ((c = getopt_long(argc, argv, "rmlhd", long_options, &option_index)) != -1) {
        switch (c) {
            case 'r':
                // Reset flag clears all iptables rules before applying new configuration
                // This provides a clean slate but can be dangerous on remote systems
                options.reset = true;
                break;
            case 'm':
                // Remove rules flag only removes YAML-managed rules (identified by comments)
                // This is safer than reset as it preserves manually configured rules
                options.remove_rules = true;
                break;
            case 'l':
                // License flag displays software license information
                // This is a read-only operation requiring no special privileges
                options.show_license = true;
                break;
            case 'h':
                // Help flag displays usage information and available options
                // This is a read-only operation requiring no special privileges
                options.help = true;
                break;
            case 'd':
                // Debug flag bypasses system validation for testing and development
                // Allows configuration parsing and validation without root privileges
                options.debug = true;
                break;
            case '?':
                // getopt_long returns '?' for unrecognized options
                // Error message is already printed by getopt_long to stderr
                throw std::invalid_argument("Unknown option");
            default:
                // Should not occur with proper option string configuration
                // This is a defensive check for programming errors
                throw std::invalid_argument("Invalid argument parsing");
        }
    }
    
    // Handle positional argument (config file path)
    // optind is set by getopt_long to the index of the first non-option argument
    if (optind < argc) {
        // Check that exactly one positional argument is provided
        // Multiple config files are not supported in this implementation
        if (optind + 1 == argc) {
            // Convert C-style string to filesystem::path for type safety and validation
            options.config_file = std::filesystem::path(argv[optind]);
        } else {
            // More than one positional argument provided
            // This could be multiple config files or extra arguments
            throw std::invalid_argument("Too many positional arguments");
        }
    }
    
    // Validate option combinations for logical consistency
    // Some options are mutually exclusive or have dependency requirements
    validateOptions(options);
    
    return options;
}

void CLIParser::validateOptions(const Options& options) {
    // License display conflicts with operational modes
    // License is informational only and shouldn't be mixed with rule operations
    if (options.show_license && (options.config_file.has_value() || options.remove_rules)) {
        throw std::invalid_argument("--license conflicts with config file and --remove-rules");
    }
    
    // Rule removal conflicts with configuration application
    // These are different operational modes that shouldn't be combined
    if (options.remove_rules && (options.config_file.has_value() || options.show_license)) {
        throw std::invalid_argument("--remove-rules conflicts with config file and --license");
    }
    
    // Reset option requires a configuration file to apply after reset
    // Reset without new configuration would leave the system with no firewall rules
    if (options.reset && !options.config_file.has_value()) {
        throw std::invalid_argument("--reset requires a config file");
    }
    
    // Ensure at least one action is specified
    // Help request is handled separately and doesn't require other options
    if (!options.config_file.has_value() && !options.remove_rules && !options.show_license && !options.help) {
        throw std::invalid_argument("No action specified");
    }
}

void CLIParser::printUsage(const std::string& program_name) {
    // Display comprehensive usage information including all options and examples
    // Format follows standard Unix command line tool conventions
    std::cout << "Usage: " << program_name << " [OPTIONS] [CONFIG_FILE]\n\n";
    std::cout << "YAML files as iptables configuration sources\n\n";
    std::cout << "Arguments:\n";
    std::cout << "  CONFIG_FILE    YAML file as iptables configuration source\n\n";
    std::cout << "Options:\n";
    // Each option includes both short and long forms with clear descriptions
    std::cout << "  -r, --reset        Reset iptables rules before applying config\n";
    std::cout << "  -m, --remove-rules Remove rules with YAML comments\n";
    std::cout << "  -l, --license      Print license information\n";
    std::cout << "  -h, --help         Show this help message\n";
    std::cout << "  -d, --debug        Debug mode (bypass system validation)\n\n";
    std::cout << "Examples:\n";
    // Provide practical examples showing common usage patterns
    std::cout << "  " << program_name << " config.yaml              Apply configuration\n";
    std::cout << "  " << program_name << " --reset config.yaml      Reset rules then apply config\n";
    std::cout << "  " << program_name << " --remove-rules           Remove all YAML rules\n";
    std::cout << "  " << program_name << " --license                Show license information\n";
}

void CLIParser::printLicense() {
    // Try to read LICENSE file from various possible locations
    // This handles different installation scenarios and build configurations
    const std::vector<std::string> license_paths = {
        "LICENSE",                                        // Current directory (development)
        "../LICENSE",                                     // Parent directory (build subdirectory)
        "../../LICENSE",                                  // Grandparent directory (nested build)
        "/usr/share/doc/iptables-compose-cpp/LICENSE"     // System installation location
    };
    
    // Search through possible license file locations in order of preference
    for (const auto& path : license_paths) {
        std::ifstream license_file(path);
        if (license_file.is_open()) {
            // License file found and readable - display its contents
            std::string line;
            while (std::getline(license_file, line)) {
                std::cout << line << '\n';
            }
            return;  // Successfully displayed license, exit function
        }
    }
    
    // Fallback license text if no LICENSE file is found
    // This ensures the application can still display license information
    // even in incomplete installations or unusual deployment scenarios
    std::cout << "iptables-compose-cpp License\n";
    std::cout << "============================\n\n";
    std::cout << "This software is provided under an open source license.\n";
    std::cout << "Please refer to the LICENSE file in the source distribution\n";
    std::cout << "for complete license terms and conditions.\n\n";
    std::cout << "For more information, visit:\n";
    std::cout << "https://github.com/your-repo/iptables-compose-cpp\n";
}

} // namespace iptables 