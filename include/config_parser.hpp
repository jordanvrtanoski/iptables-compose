/**
 * @file config_parser.hpp
 * @brief YAML configuration parsing for iptables-compose-cpp
 * @author iptables-compose-cpp Development Team
 * @date 2024
 * 
 * This file contains the ConfigParser class responsible for parsing YAML
 * configuration files and converting them to internal configuration objects.
 * Supports both file-based and string-based YAML parsing with comprehensive
 * validation and error reporting.
 */

#pragma once

#include "config.hpp"
#include <string>

namespace iptables {

/**
 * @class ConfigParser
 * @brief YAML configuration parser and serializer
 * 
 * The ConfigParser class provides static methods for loading YAML configuration
 * files and strings into Config objects, and saving Config objects back to YAML.
 * It handles all YAML parsing, validation, and serialization operations using
 * the yaml-cpp library with custom template specializations.
 */
class ConfigParser {
public:
    /**
     * @brief Load configuration from a YAML file
     * @param filename Path to the YAML configuration file
     * @return Parsed and validated Configuration object
     * @throws std::runtime_error if file cannot be read or configuration is invalid
     * @throws YAML::Exception if YAML parsing fails
     * @throws std::filesystem::filesystem_error if file access fails
     * 
     * Loads a YAML configuration file from disk, parses it using yaml-cpp,
     * validates the structure and content, and returns a Config object.
     * The file must exist and be readable by the current user.
     */
    static Config loadFromFile(const std::string& filename);
    
    /**
     * @brief Load configuration from a YAML string
     * @param yaml_content YAML content as string
     * @return Parsed and validated Configuration object
     * @throws std::runtime_error if YAML is invalid or configuration is invalid
     * @throws YAML::Exception if YAML parsing fails
     * 
     * Parses YAML content directly from a string, validates the structure
     * and content, and returns a Config object. Useful for testing and
     * dynamic configuration generation.
     */
    static Config loadFromString(const std::string& yaml_content);
    
    /**
     * @brief Save configuration to a YAML file
     * @param config Configuration object to save
     * @param filename Path where to save the YAML file
     * @throws std::runtime_error if file cannot be written
     * @throws std::filesystem::filesystem_error if file access fails
     * 
     * Serializes a Config object to YAML format and writes it to the specified
     * file. The target directory must exist and be writable by the current user.
     * This operation preserves the structure and formatting of the configuration.
     */
    static void saveToFile(const Config& config, const std::string& filename);
};

} // namespace iptables 