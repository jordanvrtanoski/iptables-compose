#include "config.hpp"
#include "chain_rule.hpp"
#include <regex>
#include <sstream>
#include <algorithm>

namespace iptables {

// PortConfig implementation
bool PortConfig::isValid() const {
    // Exactly one of port or range must be specified
    if (!port.has_value() && !range.has_value()) {
        return false;
    }
    if (port.has_value() && range.has_value()) {
        return false;
    }
    
    // Validate chain vs. action mutual exclusivity
    if (chain.has_value()) {
        if (!allow) {
            return false; // Cannot have both chain target and allow=false (drop/reject action)
        }
        if (forward.has_value()) {
            return false; // Cannot have both chain target and port forwarding
        }
    }
    
    // Validate single port
    if (port.has_value() && (*port < 1 || *port > 65535)) {
        return false;
    }
    
    // Validate port ranges
    if (range.has_value()) {
        for (const auto& range_str : *range) {
            if (!isValidPortRange(range_str)) {
                return false;
            }
        }
    }
    
    if (forward && (*forward < 1 || *forward > 65535)) {
        return false;
    }
    return true;
}

std::string PortConfig::getErrorMessage() const {
    if (!port.has_value() && !range.has_value()) {
        return "Either 'port' or 'range' must be specified";
    }
    if (port.has_value() && range.has_value()) {
        return "Cannot specify both 'port' and 'range' - they are mutually exclusive";
    }
    
    // Validate chain vs. action mutual exclusivity
    if (chain.has_value()) {
        if (!allow) {
            return "Cannot specify both 'chain' target and 'allow: false' - they are mutually exclusive";
        }
        if (forward.has_value()) {
            return "Cannot specify both 'chain' target and 'forward' port - they are mutually exclusive";
        }
    }
    
    if (port.has_value() && (*port < 1 || *port > 65535)) {
        return "Port must be between 1-65535";
    }
    if (range.has_value()) {
        for (const auto& range_str : *range) {
            if (!isValidPortRange(range_str)) {
                return "Invalid port range format: " + range_str + " (expected format: 'start-end', e.g., '1000-2000')";
            }
        }
    }
    if (forward && (*forward < 1 || *forward > 65535)) {
        return "Forward port must be between 1-65535";
    }
    return "";
}

// Helper function to validate port range format
bool PortConfig::isValidPortRange(const std::string& range_str) const {
    size_t dash_pos = range_str.find('-');
    if (dash_pos == std::string::npos) {
        return false;
    }
    
    try {
        uint16_t start = std::stoul(range_str.substr(0, dash_pos));
        uint16_t end = std::stoul(range_str.substr(dash_pos + 1));
        
        if (start < 1 || start > 65535 || end < 1 || end > 65535) {
            return false;
        }
        if (start >= end) {
            return false;
        }
        
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

// MacConfig implementation
bool MacConfig::isValid() const {
    if (mac_source.empty()) return false;
    
    // ✨ NEW: Validate chain vs. action mutual exclusivity
    // If chain is specified, it's mutually exclusive with allow=false
    if (chain.has_value() && !allow) {
        return false; // Cannot have both chain target and allow=false (drop/reject action)
    }
    
    std::regex mac_regex("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$");
    return std::regex_match(mac_source, mac_regex);
}

std::string MacConfig::getErrorMessage() const {
    if (mac_source.empty()) {
        return "MAC source cannot be empty";
    }
    
    // ✨ NEW: Chain vs. action mutual exclusivity validation
    if (chain.has_value() && !allow) {
        return "Cannot specify both 'chain' target and 'allow: false' - they are mutually exclusive";
    }
    
    if (!isValid()) {
        return "Invalid MAC address format: expected format XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX";
    }
    return "";
}

// InterfaceRuleConfig implementation
bool InterfaceRuleConfig::isValid() const {
    // At least one interface should be specified
    return input.has_value() || output.has_value();
}

std::string InterfaceRuleConfig::getErrorMessage() const {
    if (!input.has_value() && !output.has_value()) {
        return "At least one interface (input or output) must be specified";
    }
    return "";
}

// ChainRuleConfig implementation
bool ChainRuleConfig::isValid() const {
    if (name.empty()) {
        return false;
    }
    
    // Validate all rules within the chain
    for (const auto& [rule_name, rule_config] : rules) {
        if (!rule_config.isValid()) {
            return false;
        }
    }
    
    return true;
}

std::string ChainRuleConfig::getErrorMessage() const {
    if (name.empty()) {
        return "Chain name cannot be empty";
    }
    
    for (const auto& [rule_name, rule_config] : rules) {
        std::string error = rule_config.getErrorMessage();
        if (!error.empty()) {
            return "Error in rule '" + rule_name + "': " + error;
        }
    }
    
    return "";
}

// ChainConfig implementation
bool ChainConfig::isValid() const {
    for (const auto& chain_rule : chain) {
        if (!chain_rule.isValid()) {
            return false;
        }
    }
    return true;
}

std::string ChainConfig::getErrorMessage() const {
    for (const auto& chain_rule : chain) {
        std::string error = chain_rule.getErrorMessage();
        if (!error.empty()) {
            return "Error in chain '" + chain_rule.name + "': " + error;
        }
    }
    return "";
}

// FilterConfig implementation
bool FilterConfig::isValid() const {
    if (mac) {
        for (const auto& mac_rule : *mac) {
            if (!mac_rule.isValid()) {
                return false;
            }
        }
    }
    return true;
}

std::string FilterConfig::getErrorMessage() const {
    if (mac) {
        for (const auto& mac_rule : *mac) {
            std::string error = mac_rule.getErrorMessage();
            if (!error.empty()) {
                return error;
            }
        }
    }
    return "";
}

// SectionConfig implementation
bool SectionConfig::isValid() const {
    if (ports) {
        for (const auto& port : *ports) {
            if (!port.isValid()) {
                return false;
            }
        }
    }
    if (mac) {
        for (const auto& mac_rule : *mac) {
            if (!mac_rule.isValid()) {
                return false;
            }
        }
    }
    if (interface) {
        for (const auto& interface_rule : *interface) {
            if (!interface_rule.isValid()) {
                return false;
            }
        }
    }
    if (interface_config) {
        // InterfaceConfig doesn't have validation yet, but we can check basic requirements
        if (!interface_config->hasInterface() && !interface_config->hasChain()) {
            return false;
        }
    }
    if (chain_config) {
        if (!chain_config->isValid()) {
            return false;
        }
    }
    return true;
}

std::string SectionConfig::getErrorMessage() const {
    if (ports) {
        for (const auto& port : *ports) {
            std::string error = port.getErrorMessage();
            if (!error.empty()) {
                return error;
            }
        }
    }
    if (mac) {
        for (const auto& mac_rule : *mac) {
            std::string error = mac_rule.getErrorMessage();
            if (!error.empty()) {
                return error;
            }
        }
    }
    if (interface) {
        for (const auto& interface_rule : *interface) {
            std::string error = interface_rule.getErrorMessage();
            if (!error.empty()) {
                return error;
            }
        }
    }
    if (interface_config) {
        if (!interface_config->hasInterface() && !interface_config->hasChain()) {
            return "Interface configuration must specify either an interface or a chain";
        }
    }
    if (chain_config) {
        std::string error = chain_config->getErrorMessage();
        if (!error.empty()) {
            return error;
        }
    }
    return "";
}

// Config implementation
bool Config::isValid() const {
    if (filter && !filter->isValid()) {
        return false;
    }
    for (const auto& [name, section] : custom_sections) {
        if (!section.isValid()) {
            return false;
        }
    }
    for (const auto& [name, chain_config] : chain_definitions) {
        if (!chain_config.isValid()) {
            return false;
        }
    }
    return true;
}

std::string Config::getErrorMessage() const {
    if (filter) {
        std::string error = filter->getErrorMessage();
        if (!error.empty()) {
            return "Filter section: " + error;
        }
    }
    for (const auto& [name, section] : custom_sections) {
        std::string error = section.getErrorMessage();
        if (!error.empty()) {
            return "Section '" + name + "': " + error;
        }
    }
    for (const auto& [name, chain_config] : chain_definitions) {
        std::string error = chain_config.getErrorMessage();
        if (!error.empty()) {
            return "Chain definition '" + name + "': " + error;
        }
    }
    return "";
}

} // namespace iptables

// YAML conversion implementations
namespace YAML {

using namespace iptables;

// Policy conversion
YAML::Node convert<Policy>::encode(const Policy& policy) {
    Node node;
    switch (policy) {
        case Policy::Accept:
            node = "accept";
            break;
        case Policy::Drop:
            node = "drop";
            break;
        case Policy::Reject:
            node = "reject";
            break;
    }
    return node;
}

bool convert<Policy>::decode(const Node& node, Policy& policy) {
    if (!node.IsScalar()) return false;
    
    std::string value = node.as<std::string>();
    if (value == "accept") {
        policy = Policy::Accept;
    } else if (value == "drop") {
        policy = Policy::Drop;
    } else if (value == "reject") {
        policy = Policy::Reject;
    } else {
        return false;
    }
    return true;
}

// Direction conversion
YAML::Node convert<Direction>::encode(const Direction& direction) {
    Node node;
    switch (direction) {
        case Direction::Input:
            node = "input";
            break;
        case Direction::Output:
            node = "output";
            break;
        case Direction::Forward:
            node = "forward";
            break;
    }
    return node;
}

bool convert<Direction>::decode(const Node& node, Direction& direction) {
    if (!node.IsScalar()) return false;
    
    std::string value = node.as<std::string>();
    if (value == "input") {
        direction = Direction::Input;
    } else if (value == "output") {
        direction = Direction::Output;
    } else if (value == "forward") {
        direction = Direction::Forward;
    } else {
        return false;
    }
    return true;
}

// Protocol conversion
YAML::Node convert<Protocol>::encode(const Protocol& protocol) {
    Node node;
    switch (protocol) {
        case Protocol::Tcp:
            node = "tcp";
            break;
        case Protocol::Udp:
            node = "udp";
            break;
    }
    return node;
}

bool convert<Protocol>::decode(const Node& node, Protocol& protocol) {
    if (!node.IsScalar()) return false;
    
    std::string value = node.as<std::string>();
    std::transform(value.begin(), value.end(), value.begin(), ::tolower);
    
    if (value == "tcp") {
        protocol = Protocol::Tcp;
        return true;
    } else if (value == "udp") {
        protocol = Protocol::Udp;
        return true;
    }
    
    return false;
}

// Action conversion
YAML::Node convert<Action>::encode(const Action& action) {
    switch (action) {
        case Action::Accept: return Node("accept");
        case Action::Drop: return Node("drop");
        case Action::Reject: return Node("reject");
        default: return Node("accept");
    }
}

bool convert<Action>::decode(const Node& node, Action& action) {
    if (!node.IsScalar()) return false;
    
    std::string value = node.as<std::string>();
    std::transform(value.begin(), value.end(), value.begin(), ::tolower);
    
    if (value == "accept" || value == "allow") {
        action = Action::Accept;
        return true;
    } else if (value == "drop" || value == "deny") {
        action = Action::Drop;
        return true;
    } else if (value == "reject") {
        action = Action::Reject;
        return true;
    }
    
    return false;
}

// InterfaceConfig conversion
YAML::Node convert<InterfaceConfig>::encode(const InterfaceConfig& interface) {
    Node node;
    if (interface.input) {
        node["input"] = *interface.input;
    }
    if (interface.output) {
        node["output"] = *interface.output;
    }
    if (interface.chain) {
        node["chain"] = *interface.chain;
    }
    return node;
}

bool convert<InterfaceConfig>::decode(const Node& node, InterfaceConfig& interface) {
    if (!node.IsMap()) return false;
    
    if (node["input"]) {
        interface.input = node["input"].as<std::string>();
    }
    if (node["output"]) {
        interface.output = node["output"].as<std::string>();
    }
    if (node["chain"]) {
        interface.chain = node["chain"].as<std::string>();
    }
    return true;
}

// PortConfig conversion
YAML::Node convert<PortConfig>::encode(const PortConfig& config) {
    Node node;
    
    if (config.port) {
        node["port"] = *config.port;
    }
    if (config.range) {
        node["range"] = *config.range;
    }
    
    if (config.protocol != Protocol::Tcp) {
        node["protocol"] = config.protocol;
    }
    if (config.direction != Direction::Input) {
        node["direction"] = config.direction;
    }
    if (config.subnet) {
        node["subnet"] = *config.subnet;
    }
    if (config.forward) {
        node["forward"] = *config.forward;
    }
    if (!config.allow) {
        node["allow"] = config.allow;
    }
    if (config.interface) {
        node["interface"] = *config.interface;
    }
    if (config.mac_source) {
        node["mac-source"] = *config.mac_source;
    }
    if (config.chain) {
        node["chain"] = *config.chain;
    }
    
    return node;
}

bool convert<PortConfig>::decode(const Node& node, PortConfig& config) {
    if (!node.IsMap()) return false;
    
    // Check for port or range (mutually exclusive)
    bool has_port = node["port"].IsDefined();
    bool has_range = node["range"].IsDefined();
    
    if (!has_port && !has_range) {
        return false; // Must have either port or range
    }
    if (has_port && has_range) {
        return false; // Cannot have both
    }
    
    if (has_port) {
        config.port = node["port"].as<uint16_t>();
    }
    if (has_range) {
        config.range = node["range"].as<std::vector<std::string>>();
    }
    
    if (node["protocol"]) {
        config.protocol = node["protocol"].as<Protocol>();
    }
    if (node["direction"]) {
        config.direction = node["direction"].as<Direction>();
    }
    if (node["subnet"]) {
        config.subnet = node["subnet"].as<std::vector<std::string>>();
    }
    if (node["forward"]) {
        config.forward = node["forward"].as<uint16_t>();
    }
    if (node["allow"]) {
        config.allow = node["allow"].as<bool>();
    } else {
        config.allow = true; // default value
    }
    if (node["interface"]) {
        config.interface = node["interface"].as<InterfaceConfig>();
    }
    if (node["mac-source"]) {
        config.mac_source = node["mac-source"].as<std::string>();
    }
    if (node["chain"]) {
        config.chain = node["chain"].as<std::string>();
    }
    
    return true;
}

// MacConfig conversion
YAML::Node convert<MacConfig>::encode(const MacConfig& config) {
    Node node;
    node["mac-source"] = config.mac_source;
    
    if (config.direction != Direction::Input) {
        node["direction"] = config.direction;
    }
    if (config.subnet) {
        node["subnet"] = *config.subnet;
    }
    if (!config.allow) {
        node["allow"] = config.allow;
    }
    if (config.interface) {
        node["interface"] = *config.interface;
    }
    if (config.chain) {
        node["chain"] = *config.chain;
    }
    
    return node;
}

bool convert<MacConfig>::decode(const Node& node, MacConfig& config) {
    if (!node.IsMap()) return false;
    
    if (!node["mac-source"]) return false;
    config.mac_source = node["mac-source"].as<std::string>();
    
    if (node["direction"]) {
        config.direction = node["direction"].as<Direction>();
    }
    if (node["subnet"]) {
        config.subnet = node["subnet"].as<std::vector<std::string>>();
    }
    if (node["allow"]) {
        config.allow = node["allow"].as<bool>();
    } else {
        config.allow = true; // default value
    }
    if (node["interface"]) {
        config.interface = node["interface"].as<InterfaceConfig>();
    }
    if (node["chain"]) {
        config.chain = node["chain"].as<std::string>();
    }
    
    return true;
}

// InterfaceRuleConfig conversion
YAML::Node convert<InterfaceRuleConfig>::encode(const InterfaceRuleConfig& config) {
    Node node;
    
    if (config.input) {
        node["input"] = *config.input;
    }
    if (config.output) {
        node["output"] = *config.output;
    }
    if (config.direction != Direction::Input) {
        node["direction"] = config.direction;
    }
    if (!config.allow) {
        node["allow"] = config.allow;
    }
    
    return node;
}

bool convert<InterfaceRuleConfig>::decode(const Node& node, InterfaceRuleConfig& config) {
    if (!node.IsMap()) return false;
    
    if (node["input"]) {
        config.input = node["input"].as<std::string>();
    }
    if (node["output"]) {
        config.output = node["output"].as<std::string>();
    }
    if (node["direction"]) {
        config.direction = node["direction"].as<Direction>();
    }
    if (node["allow"]) {
        config.allow = node["allow"].as<bool>();
    } else {
        config.allow = true; // default value
    }
    
    return true;
}

// ChainRuleConfig conversion
YAML::Node convert<ChainRuleConfig>::encode(const ChainRuleConfig& config) {
    Node node;
    
    node["name"] = config.name;
    if (config.action != Action::Accept) {
        node["action"] = config.action;
    }
    if (!config.rules.empty()) {
        Node rules_node;
        // Preserve order by encoding each rule in sequence
        for (const auto& [rule_name, rule_config] : config.rules) {
            rules_node[rule_name] = rule_config;
        }
        node["rules"] = rules_node;
    }
    
    return node;
}

bool convert<ChainRuleConfig>::decode(const Node& node, ChainRuleConfig& config) {
    if (!node.IsMap()) return false;
    
    if (!node["name"]) return false;
    config.name = node["name"].as<std::string>();
    
    if (node["action"]) {
        config.action = node["action"].as<Action>();
    } else {
        config.action = Action::Accept; // default value
    }
    
    if (node["rules"]) {
        // Parse rules while preserving YAML order
        config.rules.clear();
        const Node& rules_node = node["rules"];
        
        // Iterate through rules in YAML order
        for (const auto& rule_item : rules_node) {
            std::string rule_name = rule_item.first.as<std::string>();
            SectionConfig rule_config = rule_item.second.as<SectionConfig>();
            config.rules.emplace_back(rule_name, std::move(rule_config));
        }
    }
    
    return true;
}

// ChainConfig conversion
YAML::Node convert<ChainConfig>::encode(const ChainConfig& config) {
    Node node;
    
    if (!config.chain.empty()) {
        node = config.chain;  // Encode directly as array
    }
    
    return node;
}

bool convert<ChainConfig>::decode(const Node& node, ChainConfig& config) {
    // Handle both cases: direct array or map with "chain" key
    if (node.IsSequence()) {
        // Direct array of ChainRuleConfig
        config.chain = node.as<std::vector<ChainRuleConfig>>();
        return true;
    } else if (node.IsMap() && node["chain"]) {
        // Map with "chain" key containing array
        config.chain = node["chain"].as<std::vector<ChainRuleConfig>>();
        return true;
    }
    
    return false;
}

// FilterConfig conversion
YAML::Node convert<FilterConfig>::encode(const FilterConfig& config) {
    Node node;
    
    if (config.input) {
        node["input"] = *config.input;
    }
    if (config.output) {
        node["output"] = *config.output;
    }
    if (config.forward) {
        node["forward"] = *config.forward;
    }
    if (config.mac) {
        node["mac"] = *config.mac;
    }
    
    return node;
}

bool convert<FilterConfig>::decode(const Node& node, FilterConfig& config) {
    if (!node.IsMap()) return false;
    
    if (node["input"]) {
        config.input = node["input"].as<Policy>();
    }
    if (node["output"]) {
        config.output = node["output"].as<Policy>();
    }
    if (node["forward"]) {
        config.forward = node["forward"].as<Policy>();
    }
    if (node["mac"]) {
        config.mac = node["mac"].as<std::vector<MacConfig>>();
    }
    
    return true;
}

// SectionConfig conversion
YAML::Node convert<SectionConfig>::encode(const SectionConfig& config) {
    Node node;
    
    if (config.ports) {
        node["ports"] = *config.ports;
    }
    if (config.mac) {
        node["mac"] = *config.mac;
    }
    if (config.interface) {
        node["interface"] = *config.interface;
    }
    if (config.interface_config) {
        node["interface"] = *config.interface_config;
    }
    if (config.action) {
        node["action"] = *config.action;
    }
    if (config.chain_config) {
        node["chain"] = *config.chain_config;
    }
    
    return node;
}

bool convert<SectionConfig>::decode(const Node& node, SectionConfig& config) {
    if (!node.IsMap()) return false;
    
    if (node["ports"]) {
        config.ports = node["ports"].as<std::vector<PortConfig>>();
    }
    if (node["mac"]) {
        config.mac = node["mac"].as<std::vector<MacConfig>>();
    }
    if (node["interface"]) {
        // Try to parse as InterfaceConfig first (for chain calls), then as array of InterfaceRuleConfig
        try {
            config.interface_config = node["interface"].as<InterfaceConfig>();
        } catch (const YAML::Exception&) {
            // If that fails, try parsing as array of InterfaceRuleConfig
            try {
                config.interface = node["interface"].as<std::vector<InterfaceRuleConfig>>();
            } catch (const YAML::Exception&) {
                return false;
            }
        }
    }
    if (node["action"]) {
        config.action = node["action"].as<Action>();
    }
    if (node["chain"]) {
        config.chain_config = node["chain"].as<ChainConfig>();
    }
    
    return true;
}

// Config conversion
YAML::Node convert<Config>::encode(const Config& config) {
    Node node;
    
    if (config.filter) {
        node["filter"] = *config.filter;
    }
    
    // Preserve order of custom sections by iterating in the same order
    for (const auto& [name, section] : config.custom_sections) {
        node[name] = section;
    }
    
    return node;
}

bool convert<Config>::decode(const Node& node, Config& config) {
    if (!node.IsMap()) return false;
    
    if (node["filter"]) {
        config.filter = node["filter"].as<FilterConfig>();
    }
    
    // Preserve the order of sections as they appear in YAML
    // Clear any existing custom sections first
    config.custom_sections.clear();
    config.chain_definitions.clear();  // ✨ Clear chain definitions as well
    
    // Iterate through the YAML node in order and add non-filter sections
    for (const auto& item : node) {
        std::string key = item.first.as<std::string>();
        if (key != "filter") {
            SectionConfig section = item.second.as<SectionConfig>();
            
            // ✨ NEW: Extract chain definitions during parsing
            if (section.chain_config) {
                // This section defines a chain, extract it to chain_definitions
                config.chain_definitions[key] = *section.chain_config;
            } else {
                // This is a regular section, add to custom_sections
                config.custom_sections.emplace_back(key, std::move(section));
            }
        }
    }
    
    return true;
}

// ✨ NEW: ChainRule YAML conversion support
template <>
struct convert<iptables::ChainRule> {
    static Node encode(const iptables::ChainRule& rule) {
        Node node;
        
        // Basic rule information
        node["direction"] = rule.getDirection();
        node["target_chain"] = rule.getTargetChain();
        node["section"] = rule.getSectionName();
        
        // Interface configuration
        if (rule.getInterface().hasInterface() || rule.getInterface().hasChain()) {
            node["interface"] = rule.getInterface();
        }
        
        // Subnet configuration
        if (!rule.getSubnets().empty()) {
            node["subnets"] = rule.getSubnets();
        }
        
        return node;
    }
    
    static bool decode(const Node& node, iptables::ChainRule& rule) {
        // ChainRule is typically created through rule processing, not directly from YAML
        // This decode method is provided for completeness but may not be used in practice
        if (!node.IsMap()) return false;
        
        // Basic validation - we would need to reconstruct the rule
        // For now, return false as ChainRule objects are created programmatically
        return false;
    }
};

} // namespace YAML 