#pragma once

#include "rule_manager.hpp"
#include "config.hpp"
#include <string>
#include <filesystem>
#include <yaml-cpp/yaml.h>

namespace iptables {

class IptablesManager {
public:
    IptablesManager() = default;
    ~IptablesManager() = default;

    // Configuration management
    bool loadConfig(const std::filesystem::path& config_path);
    bool resetRules();
    bool removeYamlRules();

    // Rule management
    bool applyRules();
    bool removeAllRules();

    // Policy management
    bool setPolicy(Direction direction, Action action);
    bool resetPolicies();

private:
    RuleManager rule_manager_;

    // Configuration processing
    bool processFilterConfig(const FilterConfig& filter);
    bool processPortConfig(const PortConfig& port, const std::string& section_name);
    bool processMacConfig(const MacConfig& mac, const std::string& section_name);
    bool processInterfaceConfig(const InterfaceRuleConfig& interface, const std::string& section_name);
    bool processActionConfig(const Action& action, const std::string& section_name);

    // Configuration parsing (legacy methods)
    bool parseFilterConfig(const YAML::Node& node);
    bool parsePortConfig(const YAML::Node& node, const std::string& section_name);
    bool parseMacConfig(const YAML::Node& node, const std::string& section_name);
    
    // Helper methods
    Direction parseDirection(const std::string& direction);
    Action parseAction(const std::string& action);
    Protocol parseProtocol(const std::string& protocol);
    InterfaceConfig parseInterface(const YAML::Node& node);
};

} // namespace iptables 