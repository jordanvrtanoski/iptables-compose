#include "cli_parser.hpp"
#include <iostream>
#include <fstream>
#include <stdexcept>
#include <vector>
#include <getopt.h>

namespace iptables {

CLIParser::Options CLIParser::parse(int argc, char* argv[]) {
    Options options;
    
    // Define long options
    static struct option long_options[] = {
        {"reset",        no_argument,       0, 'r'},
        {"remove-rules", no_argument,       0, 'm'},
        {"license",      no_argument,       0, 'l'},
        {"help",         no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    
    int option_index = 0;
    int c;
    
    // Parse options
    while ((c = getopt_long(argc, argv, "rmlh", long_options, &option_index)) != -1) {
        switch (c) {
            case 'r':
                options.reset = true;
                break;
            case 'm':
                options.remove_rules = true;
                break;
            case 'l':
                options.show_license = true;
                break;
            case 'h':
                options.help = true;
                break;
            case '?':
                throw std::invalid_argument("Unknown option");
            default:
                throw std::invalid_argument("Invalid argument parsing");
        }
    }
    
    // Handle positional argument (config file)
    if (optind < argc) {
        if (optind + 1 == argc) {
            options.config_file = std::filesystem::path(argv[optind]);
        } else {
            throw std::invalid_argument("Too many positional arguments");
        }
    }
    
    // Validate option combinations
    validateOptions(options);
    
    return options;
}

void CLIParser::validateOptions(const Options& options) {
    // --license conflicts with config and --remove-rules
    if (options.show_license && (options.config_file.has_value() || options.remove_rules)) {
        throw std::invalid_argument("--license conflicts with config file and --remove-rules");
    }
    
    // --remove-rules conflicts with config and --license
    if (options.remove_rules && (options.config_file.has_value() || options.show_license)) {
        throw std::invalid_argument("--remove-rules conflicts with config file and --license");
    }
    
    // --reset requires config file
    if (options.reset && !options.config_file.has_value()) {
        throw std::invalid_argument("--reset requires a config file");
    }
    
    // If no options provided, show help
    if (!options.config_file.has_value() && !options.remove_rules && !options.show_license && !options.help) {
        throw std::invalid_argument("No action specified");
    }
}

void CLIParser::printUsage(const std::string& program_name) {
    std::cout << "Usage: " << program_name << " [OPTIONS] [CONFIG_FILE]\n\n";
    std::cout << "YAML files as iptables configuration sources\n\n";
    std::cout << "Arguments:\n";
    std::cout << "  CONFIG_FILE    YAML file as iptables configuration source\n\n";
    std::cout << "Options:\n";
    std::cout << "  -r, --reset        Reset iptables rules before applying config\n";
    std::cout << "  -m, --remove-rules Remove rules with YAML comments\n";
    std::cout << "  -l, --license      Print license information\n";
    std::cout << "  -h, --help         Show this help message\n\n";
    std::cout << "Examples:\n";
    std::cout << "  " << program_name << " config.yaml              Apply configuration\n";
    std::cout << "  " << program_name << " --reset config.yaml      Reset rules then apply config\n";
    std::cout << "  " << program_name << " --remove-rules           Remove all YAML rules\n";
    std::cout << "  " << program_name << " --license                Show license information\n";
}

void CLIParser::printLicense() {
    // Try to read LICENSE file from various possible locations
    const std::vector<std::string> license_paths = {
        "LICENSE",
        "../LICENSE",
        "../../LICENSE",
        "/usr/share/doc/iptables-compose-cpp/LICENSE"
    };
    
    for (const auto& path : license_paths) {
        std::ifstream license_file(path);
        if (license_file.is_open()) {
            std::string line;
            while (std::getline(license_file, line)) {
                std::cout << line << '\n';
            }
            return;
        }
    }
    
    // Fallback license text if file not found
    std::cout << "iptables-compose-cpp License\n";
    std::cout << "============================\n\n";
    std::cout << "This software is provided under an open source license.\n";
    std::cout << "Please refer to the LICENSE file in the source distribution\n";
    std::cout << "for complete license terms and conditions.\n\n";
    std::cout << "For more information, visit:\n";
    std::cout << "https://github.com/your-repo/iptables-compose-cpp\n";
}

} // namespace iptables 