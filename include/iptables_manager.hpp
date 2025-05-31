#pragma once

#include "rule_manager.hpp"
#include "chain_manager.hpp"
#include "command_executor.hpp"
#include "config.hpp"
#include <string>
#include <filesystem>
#include <yaml-cpp/yaml.h>

namespace iptables {

class IptablesManager {
public:
    IptablesManager();
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
    CommandExecutor command_executor_;
    ChainManager chain_manager_;

    // Configuration processing
    bool processFilterConfig(const FilterConfig& filter);
    bool processPortConfig(const PortConfig& port, const std::string& section_name);
    bool processMacConfig(const MacConfig& mac, const std::string& section_name);
    bool processInterfaceConfig(const InterfaceRuleConfig& interface, const std::string& section_name);
    bool processActionConfig(const Action& action, const std::string& section_name);
    bool processInterfaceChainCall(const InterfaceConfig& interface, const std::string& section_name);
    
    // ✨ NEW: Chain configuration processing methods (Phase 6.3.4)
    bool createChain(const std::string& chain_name);
    bool processChainConfig(const std::string& chain_name, const ChainConfig& chain_config);
    bool processChainRuleConfig(const std::string& chain_name, const ChainRuleConfig& chain_rule);
    bool processChainRules(const std::string& chain_name, const std::map<std::string, SectionConfig>& rules);

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