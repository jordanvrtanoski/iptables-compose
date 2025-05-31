/**
 * @file cli_parser.hpp
 * @brief Command line argument parsing for iptables-compose-cpp
 * @author iptables-compose-cpp Development Team
 * @date 2024
 * 
 * This file contains the CLIParser class responsible for parsing and validating
 * command line arguments for the iptables-compose-cpp application.
 */

#pragma once

#include <filesystem>
#include <optional>
#include <string>

namespace iptables {

/**
 * @class CLIParser
 * @brief Command line interface parser for iptables-compose-cpp
 * 
 * The CLIParser class provides static methods for parsing command line arguments,
 * validating option combinations, and displaying help information. It uses getopt_long
 * for robust argument processing and supports all application command line options.
 */
class CLIParser {
public:
    /**
     * @struct Options
     * @brief Container for parsed command line options
     * 
     * This structure holds all the parsed command line options with their default values.
     * Options are validated for mutual exclusivity and logical consistency.
     */
    struct Options {
        std::optional<std::filesystem::path> config_file; ///< Path to YAML configuration file
        bool reset = false;         ///< Reset all iptables rules before applying config
        bool remove_rules = false;  ///< Remove all YAML-generated rules
        bool show_license = false;  ///< Display license information
        bool help = false;          ///< Display help information
        bool debug = false;         ///< Bypass system validation for testing
    };
    
    /**
     * @brief Parse command line arguments into Options structure
     * @param argc Number of command line arguments
     * @param argv Array of command line argument strings
     * @return Parsed options structure
     * @throws std::invalid_argument if argument parsing fails
     * @throws std::runtime_error if option validation fails
     * 
     * Parses command line arguments using getopt_long and validates the resulting
     * option combinations. Supports long and short option formats.
     */
    static Options parse(int argc, char* argv[]);
    
    /**
     * @brief Print usage information to stdout
     * @param program_name Name of the program executable
     * 
     * Displays comprehensive usage information including all available options,
     * their descriptions, and example usage patterns.
     */
    static void printUsage(const std::string& program_name);
    
    /**
     * @brief Print license information to stdout
     * 
     * Displays the MIT license text for the application. Reads license content
     * from the LICENSE file if available, otherwise displays default license text.
     */
    static void printLicense();
    
private:
    /**
     * @brief Validate parsed options for logical consistency
     * @param options The options structure to validate
     * @throws std::invalid_argument if options are inconsistent
     * 
     * Validates that option combinations make sense (e.g., cannot specify both
     * config file and remove_rules simultaneously).
     */
    static void validateOptions(const Options& options);
};

} // namespace iptables 