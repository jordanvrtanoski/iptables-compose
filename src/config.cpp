#include "config.hpp"
#include <regex>
#include <sstream>
#include <algorithm>

namespace iptables {

// PortConfig implementation
bool PortConfig::isValid() const {
    if (port < 1 || port > 65535) {
        return false;
    }
    if (forward && (*forward < 1 || *forward > 65535)) {
        return false;
    }
    return true;
}

std::string PortConfig::getErrorMessage() const {
    if (port < 1 || port > 65535) {
        return "Port must be between 1-65535";
    }
    if (forward && (*forward < 1 || *forward > 65535)) {
        return "Forward port must be between 1-65535";
    }
    return "";
}

// MacConfig implementation
bool MacConfig::isValid() const {
    if (mac_source.empty()) return false;
    
    std::regex mac_regex("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$");
    return std::regex_match(mac_source, mac_regex);
}

std::string MacConfig::getErrorMessage() const {
    if (mac_source.empty()) {
        return "MAC source cannot be empty";
    }
    if (!isValid()) {
        return "Invalid MAC address format: expected format XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX";
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
    if (value == "tcp") {
        protocol = Protocol::Tcp;
    } else if (value == "udp") {
        protocol = Protocol::Udp;
    } else {
        return false;
    }
    return true;
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
    return true;
}

// PortConfig conversion
YAML::Node convert<PortConfig>::encode(const PortConfig& config) {
    Node node;
    node["port"] = config.port;
    
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
    
    return node;
}

bool convert<PortConfig>::decode(const Node& node, PortConfig& config) {
    if (!node.IsMap()) return false;
    
    if (!node["port"]) return false;
    config.port = node["port"].as<uint16_t>();
    
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
    
    return true;
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
    
    return true;
}

// Config conversion
YAML::Node convert<Config>::encode(const Config& config) {
    Node node;
    
    if (config.filter) {
        node["filter"] = *config.filter;
    }
    
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
    
    // Parse all other sections as custom sections
    for (const auto& item : node) {
        std::string key = item.first.as<std::string>();
        if (key != "filter") {
            config.custom_sections[key] = item.second.as<SectionConfig>();
        }
    }
    
    return true;
}

} // namespace YAML 