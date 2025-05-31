#include "config_parser.hpp"
#include <yaml-cpp/yaml.h>
#include <fstream>
#include <stdexcept>

namespace iptables {

Config ConfigParser::loadFromFile(const std::string& filename) {
    try {
        // Load YAML file using yaml-cpp library
        // YAML::LoadFile throws YAML::Exception for file access errors or invalid YAML syntax
        // This handles UTF-8 encoding and supports all YAML 1.2 features
        YAML::Node yamlNode = YAML::LoadFile(filename);
        
        // Convert YAML node to Config object using custom template specializations
        // The as<Config>() call triggers the YAML::convert<Config>::decode() method
        // which recursively parses all nested configuration structures
        Config config = yamlNode.as<Config>();
        
        // Validate the parsed configuration for logical consistency
        // This checks field constraints, mutual exclusivity, and cross-references
        // Validation occurs after YAML parsing to ensure all fields are populated
        if (!config.isValid()) {
            // Configuration validation failed - throw with detailed error message
            // getErrorMessage() provides specific information about validation failures
            throw std::runtime_error("Invalid configuration: " + config.getErrorMessage());
        }
        
        return config;
    } catch (const YAML::Exception& e) {
        // YAML parsing errors include syntax errors, type conversion failures, and file access issues
        // These are typically user configuration errors rather than programming errors
        throw std::runtime_error("YAML parsing error: " + std::string(e.what()));
    } catch (const std::exception& e) {
        // Catch any other standard exceptions from validation or type conversion
        // This provides a consistent error reporting interface for all configuration errors
        throw std::runtime_error("Configuration loading error: " + std::string(e.what()));
    }
}

Config ConfigParser::loadFromString(const std::string& yaml_content) {
    try {
        // Parse YAML content from string rather than file
        // YAML::Load supports the same syntax as LoadFile but operates on in-memory content
        // This is useful for testing, dynamic configuration generation, or embedded YAML
        YAML::Node yamlNode = YAML::Load(yaml_content);
        
        // Convert YAML node to Config object using the same mechanism as file loading
        // This ensures consistent behavior between file and string-based configuration
        Config config = yamlNode.as<Config>();
        
        // Apply the same validation logic as file-based loading
        // Configuration validation is independent of the YAML source (file vs string)
        if (!config.isValid()) {
            // Validation failure handling identical to file loading for consistency
            throw std::runtime_error("Invalid configuration: " + config.getErrorMessage());
        }
        
        return config;
    } catch (const YAML::Exception& e) {
        // YAML parsing errors from string content typically indicate syntax issues
        // Error messages include line and column information for debugging
        throw std::runtime_error("YAML parsing error: " + std::string(e.what()));
    } catch (const std::exception& e) {
        // Handle validation errors and type conversion failures consistently
        throw std::runtime_error("Configuration loading error: " + std::string(e.what()));
    }
}

void ConfigParser::saveToFile(const Config& config, const std::string& filename) {
    try {
        // Convert Config object back to YAML node structure
        // Uses the YAML::convert<Config>::encode() method to serialize the configuration
        // This preserves the original structure and formatting where possible
        YAML::Node yamlNode = YAML::convert<Config>::encode(config);
        
        // Write YAML content to file with proper formatting
        // The output stream operator formats the YAML with appropriate indentation and structure
        // This produces human-readable YAML that can be edited and reloaded
        std::ofstream file(filename);
        if (!file.is_open()) {
            throw std::runtime_error("Unable to open file for writing: " + filename);
        }
        file << yamlNode;
        
        // File is automatically closed by ofstream destructor
        // Any write errors will be detected during stream operations
    } catch (const std::exception& e) {
        // Handle file I/O errors, serialization failures, and filesystem issues
        // This provides consistent error reporting for configuration saving operations
        throw std::runtime_error("Configuration saving error: " + std::string(e.what()));
    }
}

} // namespace iptables 