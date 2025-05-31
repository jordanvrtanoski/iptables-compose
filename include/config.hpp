#pragma once

#include "rule.hpp"
#include <string>
#include <vector>
#include <map>
#include <optional>
#include <yaml-cpp/yaml.h>

namespace iptables {

// Enum for policies (matching Rust Policy enum)
enum class Policy {
    Accept,
    Drop,
    Reject
};

// Port configuration matching Rust PortConfig
struct PortConfig {
    uint16_t port;
    Protocol protocol = Protocol::Tcp;
    Direction direction = Direction::Input;
    std::optional<std::vector<std::string>> subnet;
    std::optional<uint16_t> forward;
    bool allow = true;
    std::optional<InterfaceConfig> interface;
    std::optional<std::string> mac_source;

    bool isValid() const;
    std::string getErrorMessage() const;
};

// MAC configuration matching Rust MacConfig
struct MacConfig {
    std::string mac_source;
    Direction direction = Direction::Input;
    std::optional<std::vector<std::string>> subnet;
    bool allow = true;
    std::optional<InterfaceConfig> interface;

    bool isValid() const;
    std::string getErrorMessage() const;
};

// Filter configuration matching Rust FilterConfig
struct FilterConfig {
    std::optional<Policy> input;
    std::optional<Policy> output;
    std::optional<Policy> forward;
    std::optional<std::vector<MacConfig>> mac;

    bool isValid() const;
    std::string getErrorMessage() const;
};

// Interface rule configuration (new structure for standalone interface rules)
struct InterfaceRuleConfig {
    std::optional<std::string> input;
    std::optional<std::string> output;
    Direction direction = Direction::Input;
    bool allow = true;

    bool isValid() const;
    std::string getErrorMessage() const;
};

// Section configuration matching Rust SectionConfig
// Note: Order of rules within each vector is preserved from YAML
struct SectionConfig {
    std::optional<std::vector<PortConfig>> ports;
    std::optional<std::vector<MacConfig>> mac;
    std::optional<std::vector<InterfaceRuleConfig>> interface;
    // Action field for general catch-all rules (e.g., dropall section)
    std::optional<Action> action;

    bool isValid() const;
    std::string getErrorMessage() const;
};

// Root configuration matching Rust Config
struct Config {
    std::optional<FilterConfig> filter;
    // Use vector of pairs to preserve the order of sections as they appear in YAML
    std::vector<std::pair<std::string, SectionConfig>> custom_sections;

    bool isValid() const;
    std::string getErrorMessage() const;
};

}  // namespace iptables

// YAML template specializations must be in the YAML namespace
namespace YAML {

template<>
struct convert<iptables::Policy> {
    static Node encode(const iptables::Policy& policy);
    static bool decode(const Node& node, iptables::Policy& policy);
};

template<>
struct convert<iptables::Direction> {
    static Node encode(const iptables::Direction& direction);
    static bool decode(const Node& node, iptables::Direction& direction);
};

template<>
struct convert<iptables::Protocol> {
    static Node encode(const iptables::Protocol& protocol);
    static bool decode(const Node& node, iptables::Protocol& protocol);
};

template<>
struct convert<iptables::Action> {
    static Node encode(const iptables::Action& action);
    static bool decode(const Node& node, iptables::Action& action);
};

template<>
struct convert<iptables::InterfaceConfig> {
    static Node encode(const iptables::InterfaceConfig& interface);
    static bool decode(const Node& node, iptables::InterfaceConfig& interface);
};

template<>
struct convert<iptables::PortConfig> {
    static Node encode(const iptables::PortConfig& config);
    static bool decode(const Node& node, iptables::PortConfig& config);
};

template<>
struct convert<iptables::MacConfig> {
    static Node encode(const iptables::MacConfig& config);
    static bool decode(const Node& node, iptables::MacConfig& config);
};

template<>
struct convert<iptables::InterfaceRuleConfig> {
    static Node encode(const iptables::InterfaceRuleConfig& config);
    static bool decode(const Node& node, iptables::InterfaceRuleConfig& config);
};

template<>
struct convert<iptables::FilterConfig> {
    static Node encode(const iptables::FilterConfig& config);
    static bool decode(const Node& node, iptables::FilterConfig& config);
};

template<>
struct convert<iptables::SectionConfig> {
    static Node encode(const iptables::SectionConfig& config);
    static bool decode(const Node& node, iptables::SectionConfig& config);
};

template<>
struct convert<iptables::Config> {
    static Node encode(const iptables::Config& config);
    static bool decode(const Node& node, iptables::Config& config);
};

}  // namespace YAML