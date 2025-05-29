#pragma once

#include "config.hpp"
#include <string>

namespace iptables {

class ConfigParser {
public:
    /**
     * Load configuration from a YAML file
     * @param filename Path to the YAML configuration file
     * @return Parsed and validated Configuration object
     * @throws std::runtime_error if file cannot be read or configuration is invalid
     */
    static Config loadFromFile(const std::string& filename);
    
    /**
     * Load configuration from a YAML string
     * @param yaml_content YAML content as string
     * @return Parsed and validated Configuration object
     * @throws std::runtime_error if YAML is invalid or configuration is invalid
     */
    static Config loadFromString(const std::string& yaml_content);
    
    /**
     * Save configuration to a YAML file
     * @param config Configuration object to save
     * @param filename Path where to save the YAML file
     * @throws std::runtime_error if file cannot be written
     */
    static void saveToFile(const Config& config, const std::string& filename);
};

} // namespace iptables 