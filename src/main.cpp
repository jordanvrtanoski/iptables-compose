#include <iostream>
#include <string>
#include <filesystem>
#include "iptables_manager.hpp"
#include "cli_parser.hpp"
#include "system_utils.hpp"

int main(int argc, char* argv[]) {
    try {
        auto options = iptables::CLIParser::parse(argc, argv);
        
        // Handle help option first (no system validation needed)
        if (options.help) {
            iptables::CLIParser::printUsage(argv[0]);
            return 0;
        }
        
        // Handle license option (no system validation needed)
        if (options.show_license) {
            iptables::CLIParser::printLicense();
            return 0;
        }
        
        // For all other operations, validate system requirements
        std::cout << "Validating system requirements..." << std::endl;
        try {
            iptables::SystemUtils::validateSystemRequirements();
            std::cout << "System validation passed." << std::endl;
        } catch (const std::runtime_error& e) {
            std::cerr << "\nSystem validation failed. Use --help for usage information." << std::endl;
            return 1;
        }
        
        // Handle rule removal without config
        if (options.remove_rules) {
            std::cout << "Removing all YAML-managed iptables rules..." << std::endl;
            
            iptables::IptablesManager manager;
            if (manager.removeYamlRules()) {
                std::cout << "Successfully removed all YAML-managed rules." << std::endl;
                return 0;
            } else {
                std::cerr << "Failed to remove YAML-managed rules." << std::endl;
                return 1;
            }
        }
        
        // Handle config file processing
        if (options.config_file) {
            const auto& config_path = *options.config_file;
            
            // Validate config file exists and is readable
            if (!std::filesystem::exists(config_path)) {
                std::cerr << "Error: Configuration file does not exist: " << config_path.string() << std::endl;
                return 1;
            }
            
            if (!std::filesystem::is_regular_file(config_path)) {
                std::cerr << "Error: Path is not a regular file: " << config_path.string() << std::endl;
                return 1;
            }
            
            std::cout << "Processing configuration file: " << config_path.string() << std::endl;
            
            iptables::IptablesManager manager;
            
            // Handle rule reset before config application
            if (options.reset) {
                std::cout << "Resetting all iptables rules..." << std::endl;
                if (!manager.resetRules()) {
                    std::cerr << "Failed to reset iptables rules. Aborting configuration application." << std::endl;
                    return 1;
                }
                std::cout << "Successfully reset iptables rules." << std::endl;
            }
            
            // Full config processing workflow
            std::cout << "Loading and applying configuration..." << std::endl;
            if (!manager.loadConfig(config_path)) {
                std::cerr << "Failed to load or apply configuration: " << config_path.string() << std::endl;
                std::cerr << "Please check the configuration file format and iptables permissions." << std::endl;
                return 1;
            }
            
            std::cout << "Configuration applied successfully!" << std::endl;
            std::cout << "All iptables rules have been updated according to the configuration." << std::endl;
            return 0;
        }
        
        // Should not reach here due to validation in CLIParser
        std::cerr << "Internal error: No valid action specified." << std::endl;
        iptables::CLIParser::printUsage(argv[0]);
        return 1;
        
    } catch (const std::invalid_argument& e) {
        if (std::string(e.what()) == "No action specified") {
            iptables::CLIParser::printUsage(argv[0]);
        } else {
            std::cerr << "Error: " << e.what() << std::endl;
            std::cerr << "Use --help for usage information." << std::endl;
        }
        return 1;
    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "File system error: " << e.what() << std::endl;
        return 1;
    } catch (const std::runtime_error& e) {
        std::cerr << "Runtime error: " << e.what() << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Unexpected error: " << e.what() << std::endl;
        std::cerr << "Please report this issue with the command you were trying to execute." << std::endl;
        return 1;
    }
} 