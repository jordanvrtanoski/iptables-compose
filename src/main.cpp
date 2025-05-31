#include <iostream>
#include <string>
#include <filesystem>
#include "iptables_manager.hpp"
#include "cli_parser.hpp"
#include "system_utils.hpp"
#include "config_parser.hpp"
#include "rule_validator.hpp"

int main(int argc, char* argv[]) {
    try {
        // Parse command line arguments using getopt_long for robust argument handling
        // This will throw std::invalid_argument for invalid options or combinations
        auto options = iptables::CLIParser::parse(argc, argv);
        
        // Handle help option first (no system validation needed)
        // Help can be shown regardless of system state or privileges
        if (options.help) {
            iptables::CLIParser::printUsage(argv[0]);
            return 0;
        }
        
        // Handle license option (no system validation needed)  
        // License display is a read-only operation that doesn't require root privileges
        if (options.show_license) {
            iptables::CLIParser::printLicense();
            return 0;
        }
        
        // For all iptables operations, validate system requirements first
        // This prevents confusing error messages later in the process
        std::cout << "Validating system requirements..." << std::endl;
        try {
            // In debug mode, skip system validation to allow testing without root privileges
            // This enables developers to test configuration parsing and validation
            if (!options.debug) {
                // Check for root privileges, iptables availability, and execution permissions
                // Throws std::runtime_error with detailed error messages if validation fails
                iptables::SystemUtils::validateSystemRequirements();
                std::cout << "System validation passed." << std::endl;
            } else {
                std::cout << "Debug mode: Skipping system validation." << std::endl;
            }
        } catch (const std::runtime_error& e) {
            // System validation errors are terminal - we cannot proceed without proper privileges
            // The error message from validateSystemRequirements() already contains detailed info
            std::cerr << "\nSystem validation failed. Use --help for usage information." << std::endl;
            return 1;
        }
        
        // Handle rule removal without config
        // This operation removes all rules with YAML comment signatures from iptables
        if (options.remove_rules) {
            std::cout << "Removing all YAML-managed iptables rules..." << std::endl;
            
            // Create manager instance for rule operations
            // The manager handles all iptables interactions and error reporting
            iptables::IptablesManager manager;
            if (manager.removeYamlRules()) {
                std::cout << "Successfully removed all YAML-managed rules." << std::endl;
                return 0;
            } else {
                // Rule removal failure could be due to iptables errors, permission issues,
                // or rules being locked by other processes
                std::cerr << "Failed to remove YAML-managed rules." << std::endl;
                return 1;
            }
        }
        
        // Handle config file processing
        // This is the main application workflow for applying firewall configurations
        if (options.config_file) {
            const auto& config_path = *options.config_file;
            
            // Validate config file exists and is readable before attempting to parse
            // Early validation prevents confusing YAML parser errors
            if (!std::filesystem::exists(config_path)) {
                std::cerr << "Error: Configuration file does not exist: " << config_path.string() << std::endl;
                return 1;
            }
            
            // Ensure the path points to a regular file, not a directory or special file
            // This prevents attempts to parse directories or device files as YAML
            if (!std::filesystem::is_regular_file(config_path)) {
                std::cerr << "Error: Path is not a regular file: " << config_path.string() << std::endl;
                return 1;
            }
            
            std::cout << "Processing configuration file: " << config_path.string() << std::endl;
            
            // Create manager instance for configuration processing
            iptables::IptablesManager manager;
            
            // Debug mode: validation-only workflow without applying iptables rules
            // This allows safe testing of configuration files and rule validation
            if (options.debug) {
                std::cout << "Debug mode: Loading configuration for validation only..." << std::endl;
                
                // Load and validate configuration without applying to iptables
                // This workflow is safe to run without root privileges
                try {
                    // Parse YAML configuration file into internal Config structure
                    // This validates YAML syntax and converts to typed configuration objects
                    iptables::Config config = iptables::ConfigParser::loadFromFile(config_path.string());
                    std::cout << "Configuration loaded successfully" << std::endl;
                    
                    // Run rule order validation to detect potential configuration issues
                    // This analyzes rule selectivity and identifies unreachable or conflicting rules
                    std::cout << "Validating rule order..." << std::endl;
                    auto warnings = iptables::RuleValidator::validateRuleOrder(config);
                    
                    // Report any validation warnings to help users identify potential issues
                    // Warnings don't prevent configuration application but indicate possible problems
                    if (!warnings.empty()) {
                        std::cout << "Found " << warnings.size() << " potential rule ordering issue(s):" << std::endl;
                        for (const auto& warning : warnings) {
                            // Categorize warnings by type for better user understanding
                            switch (warning.type) {
                                case iptables::ValidationWarning::Type::UnreachableRule:
                                    std::cout << "  WARNING (Unreachable Rule): " << warning.message << std::endl;
                                    break;
                                case iptables::ValidationWarning::Type::RedundantRule:
                                    std::cout << "  WARNING (Redundant Rule): " << warning.message << std::endl;
                                    break;
                                case iptables::ValidationWarning::Type::SubnetOverlap:
                                    std::cout << "  WARNING (Subnet Overlap): " << warning.message << std::endl;
                                    break;
                            }
                        }
                        // Provide guidance on how to address the warnings
                        std::cout << "These warnings indicate potential misconfigurations where rules may not work as expected." << std::endl;
                        std::cout << "Consider reordering rules to place more specific conditions before general ones." << std::endl;
                    } else {
                        std::cout << "Rule order validation passed - no issues detected." << std::endl;
                    }
                    
                    std::cout << "Debug mode: Configuration validation completed. No iptables rules were modified." << std::endl;
                    return 0;
                    
                } catch (const std::exception& e) {
                    // Configuration loading or validation errors in debug mode
                    // These could be YAML syntax errors, invalid configurations, or validation failures
                    std::cerr << "Failed to load or validate configuration: " << e.what() << std::endl;
                    return 1;
                }
            }
            
            // Handle rule reset before config application
            // Reset clears all existing iptables rules to start with a clean slate
            if (options.reset) {
                std::cout << "Resetting all iptables rules..." << std::endl;
                // Reset failure is critical - we abort configuration application to prevent
                // partial state where old rules might conflict with new ones
                if (!manager.resetRules()) {
                    std::cerr << "Failed to reset iptables rules. Aborting configuration application." << std::endl;
                    return 1;
                }
                std::cout << "Successfully reset iptables rules." << std::endl;
            }
            
            // Full config processing workflow - the main application function
            // This loads the configuration, validates it, and applies all rules to iptables
            std::cout << "Loading and applying configuration..." << std::endl;
            if (!manager.loadConfig(config_path)) {
                // Configuration application failure could be due to:
                // - YAML parsing errors
                // - Invalid configuration structure  
                // - iptables command execution failures
                // - Permission or system issues
                std::cerr << "Failed to load or apply configuration: " << config_path.string() << std::endl;
                std::cerr << "Please check the configuration file format and iptables permissions." << std::endl;
                return 1;
            }
            
            // Success: all configuration has been applied to iptables
            std::cout << "Configuration applied successfully!" << std::endl;
            std::cout << "All iptables rules have been updated according to the configuration." << std::endl;
            return 0;
        }
        
        // Should not reach here due to validation in CLIParser::validateOptions()
        // This is a defensive check for internal logic errors
        std::cerr << "Internal error: No valid action specified." << std::endl;
        iptables::CLIParser::printUsage(argv[0]);
        return 1;
        
    } catch (const std::invalid_argument& e) {
        // Handle command line parsing errors
        // Special case: "No action specified" triggers help display
        if (std::string(e.what()) == "No action specified") {
            iptables::CLIParser::printUsage(argv[0]);
        } else {
            // Other invalid_argument exceptions are option parsing errors
            std::cerr << "Error: " << e.what() << std::endl;
            std::cerr << "Use --help for usage information." << std::endl;
        }
        return 1;
    } catch (const std::filesystem::filesystem_error& e) {
        // Handle file system related errors (file not found, permission denied, etc.)
        // These typically occur during configuration file access
        std::cerr << "File system error: " << e.what() << std::endl;
        return 1;
    } catch (const std::runtime_error& e) {
        // Handle runtime errors from system validation, iptables operations, etc.
        // These are typically operational errors rather than programming errors
        std::cerr << "Runtime error: " << e.what() << std::endl;
        return 1;
    } catch (const std::exception& e) {
        // Catch-all for any other standard exceptions
        // This should rarely occur but provides a safety net for unexpected errors
        std::cerr << "Unexpected error: " << e.what() << std::endl;
        std::cerr << "Please report this issue with the command you were trying to execute." << std::endl;
        return 1;
    }
} 