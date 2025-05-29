#include "config_parser.hpp"
#include <yaml-cpp/yaml.h>
#include <fstream>
#include <stdexcept>

namespace iptables {

Config ConfigParser::loadFromFile(const std::string& filename) {
    try {
        YAML::Node yamlNode = YAML::LoadFile(filename);
        Config config = yamlNode.as<Config>();
        
        if (!config.isValid()) {
            throw std::runtime_error("Invalid configuration: " + config.getErrorMessage());
        }
        
        return config;
    } catch (const YAML::Exception& e) {
        throw std::runtime_error("YAML parsing error: " + std::string(e.what()));
    } catch (const std::exception& e) {
        throw std::runtime_error("Configuration loading error: " + std::string(e.what()));
    }
}

Config ConfigParser::loadFromString(const std::string& yaml_content) {
    try {
        YAML::Node yamlNode = YAML::Load(yaml_content);
        Config config = yamlNode.as<Config>();
        
        if (!config.isValid()) {
            throw std::runtime_error("Invalid configuration: " + config.getErrorMessage());
        }
        
        return config;
    } catch (const YAML::Exception& e) {
        throw std::runtime_error("YAML parsing error: " + std::string(e.what()));
    } catch (const std::exception& e) {
        throw std::runtime_error("Configuration loading error: " + std::string(e.what()));
    }
}

void ConfigParser::saveToFile(const Config& config, const std::string& filename) {
    try {
        YAML::Node yamlNode = YAML::convert<Config>::encode(config);
        std::ofstream file(filename);
        file << yamlNode;
    } catch (const std::exception& e) {
        throw std::runtime_error("Configuration saving error: " + std::string(e.what()));
    }
}

} // namespace iptables 