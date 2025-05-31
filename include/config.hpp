/**
 * @file config.hpp
 * @brief Configuration structures and YAML serialization for iptables-compose-cpp
 * @author iptables-compose-cpp Development Team
 * @date 2024
 * 
 * This file contains the complete configuration system for iptables-compose-cpp,
 * including all data structures for representing iptables rules, filters, chains,
 * and their hierarchical organization. It also provides YAML serialization
 * capabilities through yaml-cpp template specializations.
 * 
 * The configuration system supports:
 * - Port-based rules with single ports, ranges, and multiport configurations
 * - MAC address filtering rules
 * - Interface-based rules and configurations
 * - Custom chain definitions and cross-chain references
 * - Filter policies for built-in chains (INPUT, OUTPUT, FORWARD)
 * - Hierarchical section organization with dependency resolution
 */

#pragma once

#include "rule.hpp"
#include <string>
#include <vector>
#include <map>
#include <optional>
#include <yaml-cpp/yaml.h>

namespace iptables {

// Forward declarations to resolve circular dependencies
struct SectionConfig;
struct ChainRuleConfig;
struct ChainConfig;

/**
 * @enum Policy
 * @brief Default chain policies for iptables filter chains
 * 
 * Defines the default actions for packets that don't match any rules
 * in built-in chains (INPUT, OUTPUT, FORWARD). These correspond to
 * iptables policy targets and determine system security posture.
 */
enum class Policy {
    Accept,  ///< Allow packets through (permissive)
    Drop,    ///< Silently discard packets (secure)
    Reject   ///< Actively reject packets with ICMP response (informative)
};

/**
 * @struct PortConfig
 * @brief Configuration for port-based iptables rules
 * 
 * Represents a single port rule configuration that can handle:
 * - Single port filtering (port field)
 * - Port range filtering (range field with multiple ranges)
 * - Protocol specification (TCP/UDP)
 * - Direction control (INPUT/OUTPUT)
 * - Subnet restrictions
 * - Port forwarding (NAT rules)
 * - Interface binding
 * - MAC source filtering
 * - Custom chain targeting
 * 
 * The port and range fields are mutually exclusive. The allow field
 * determines whether to ACCEPT or DROP, while chain provides direct
 * targeting to custom chains.
 */
struct PortConfig {
    std::optional<uint16_t> port;  ///< Single port number (mutually exclusive with range)
    std::optional<std::vector<std::string>> range;  ///< Port ranges like ["1000-2000", "3000-4000"]
    Protocol protocol = Protocol::Tcp;  ///< Protocol type (TCP or UDP)
    Direction direction = Direction::Input;  ///< Traffic direction (INPUT or OUTPUT)
    std::optional<std::vector<std::string>> subnet;  ///< Source/destination subnet restrictions
    std::optional<uint16_t> forward;  ///< Port forwarding target port
    bool allow = true;  ///< Whether to ACCEPT (true) or DROP (false) traffic
    std::optional<InterfaceConfig> interface;  ///< Network interface configuration
    std::optional<std::string> mac_source;  ///< MAC address source filter
    std::optional<std::string> chain;  ///< Direct chain target (mutually exclusive with allow/forward)

    /**
     * @brief Validate the port configuration
     * @return true if configuration is valid and consistent
     * 
     * Checks for:
     * - Mutual exclusivity of port and range fields
     * - Valid port numbers and ranges
     * - Logical consistency of allow/forward/chain settings
     * - Valid protocol and direction values
     */
    bool isValid() const;
    
    /**
     * @brief Get detailed error message for invalid configurations
     * @return Human-readable error description or empty string if valid
     * 
     * Provides specific information about configuration errors,
     * including which fields are invalid and why.
     */
    std::string getErrorMessage() const;

private:
    /**
     * @brief Validate a port range string format
     * @param range_str Port range in format "start-end"
     * @return true if range format is valid
     * 
     * Validates that the range string follows the correct format
     * and that start <= end within valid port number bounds.
     */
    bool isValidPortRange(const std::string& range_str) const;
};

/**
 * @struct MacConfig
 * @brief Configuration for MAC address-based iptables rules
 * 
 * Represents MAC address filtering rules that can:
 * - Filter by source MAC address
 * - Apply to specific traffic directions
 * - Restrict to specific subnets
 * - Bind to network interfaces
 * - Target custom chains
 * 
 * Used for Layer 2 filtering and device-specific access control.
 */
struct MacConfig {
    std::string mac_source;  ///< Source MAC address in XX:XX:XX:XX:XX:XX format
    Direction direction = Direction::Input;  ///< Traffic direction (INPUT or OUTPUT)
    std::optional<std::vector<std::string>> subnet;  ///< Source/destination subnet restrictions
    bool allow = true;  ///< Whether to ACCEPT (true) or DROP (false) traffic
    std::optional<InterfaceConfig> interface;  ///< Network interface configuration
    std::optional<std::string> chain;  ///< Direct chain target (mutually exclusive with allow)

    /**
     * @brief Validate the MAC configuration
     * @return true if configuration is valid
     * 
     * Checks MAC address format, direction validity, and
     * logical consistency of allow/chain settings.
     */
    bool isValid() const;
    
    /**
     * @brief Get detailed error message for invalid configurations
     * @return Human-readable error description or empty string if valid
     */
    std::string getErrorMessage() const;
};

/**
 * @struct FilterConfig
 * @brief Configuration for iptables filter table default policies
 * 
 * Configures the default policies for the three built-in chains
 * in the filter table (INPUT, OUTPUT, FORWARD). These policies
 * determine what happens to packets that don't match any rules.
 * 
 * Also contains MAC-based rules that apply globally to the filter table.
 */
struct FilterConfig {
    std::optional<Policy> input;  ///< Default policy for INPUT chain
    std::optional<Policy> output;  ///< Default policy for OUTPUT chain
    std::optional<Policy> forward;  ///< Default policy for FORWARD chain
    std::optional<std::vector<MacConfig>> mac;  ///< Global MAC filtering rules

    /**
     * @brief Validate the filter configuration
     * @return true if all policies and MAC rules are valid
     */
    bool isValid() const;
    
    /**
     * @brief Get detailed error message for invalid configurations
     * @return Human-readable error description or empty string if valid
     */
    std::string getErrorMessage() const;
};

/**
 * @struct InterfaceRuleConfig
 * @brief Configuration for interface-based rules
 * 
 * Represents rules that control traffic based on network interfaces
 * without specific port or MAC requirements. Used for broad
 * interface-level access control and traffic shaping.
 */
struct InterfaceRuleConfig {
    std::optional<std::string> input;  ///< Input interface name (e.g., "eth0")
    std::optional<std::string> output;  ///< Output interface name (e.g., "wlan0")
    Direction direction = Direction::Input;  ///< Primary traffic direction
    bool allow = true;  ///< Whether to ACCEPT (true) or DROP (false) traffic

    /**
     * @brief Validate the interface rule configuration
     * @return true if interface names and direction are valid
     */
    bool isValid() const;
    
    /**
     * @brief Get detailed error message for invalid configurations
     * @return Human-readable error description or empty string if valid
     */
    std::string getErrorMessage() const;
};

/**
 * @struct ChainRuleConfig
 * @brief Configuration for individual custom chain definitions
 * 
 * Represents a single custom chain with its default action and
 * collection of named rule groups. Custom chains can be referenced
 * by other rules for modular firewall organization.
 */
struct ChainRuleConfig {
    std::string name;  ///< Chain name (e.g., "MAC_RULES_ETH1")
    Action action = Action::Accept;  ///< Default action for the chain
    std::map<std::string, SectionConfig> rules;  ///< Named rule groups within chain

    /**
     * @brief Validate the chain rule configuration
     * @return true if chain name is valid and rules are consistent
     */
    bool isValid() const;
    
    /**
     * @brief Get detailed error message for invalid configurations
     * @return Human-readable error description or empty string if valid
     */
    std::string getErrorMessage() const;
};

/**
 * @struct ChainConfig
 * @brief Configuration container for multiple chain definitions
 * 
 * Contains an array of custom chain definitions, typically used
 * in sections that define multiple related chains.
 */
struct ChainConfig {
    std::vector<ChainRuleConfig> chain;  ///< Array of chain definitions

    /**
     * @brief Validate all chain configurations
     * @return true if all chains are valid and names are unique
     */
    bool isValid() const;
    
    /**
     * @brief Get detailed error message for invalid configurations
     * @return Human-readable error description or empty string if valid
     */
    std::string getErrorMessage() const;
};

/**
 * @struct SectionConfig
 * @brief Configuration for a named section of iptables rules
 * 
 * Represents a logical grouping of related iptables rules. Sections
 * provide organizational structure and can contain various types of
 * rules including ports, MAC addresses, interfaces, and chain definitions.
 * 
 * The order of rules within each vector is preserved from the YAML
 * configuration to maintain rule precedence in iptables.
 */
struct SectionConfig {
    std::optional<std::vector<PortConfig>> ports;  ///< Port-based rules
    std::optional<std::vector<MacConfig>> mac;  ///< MAC address rules
    std::optional<std::vector<InterfaceRuleConfig>> interface;  ///< Interface rules
    std::optional<InterfaceConfig> interface_config;  ///< Interface configuration for chain calls
    std::optional<Action> action;  ///< Action field for general catch-all rules (e.g., dropall section)
    std::optional<ChainConfig> chain_config;  ///< Chain configuration for chain definition sections

    /**
     * @brief Validate the section configuration
     * @return true if all contained rules and configurations are valid
     */
    bool isValid() const;
    
    /**
     * @brief Get detailed error message for invalid configurations
     * @return Human-readable error description or empty string if valid
     */
    std::string getErrorMessage() const;
};

/**
 * @struct Config
 * @brief Root configuration structure for iptables-compose-cpp
 * 
 * The main configuration container that holds all iptables rules,
 * filter policies, and custom sections. This structure represents
 * the complete firewall configuration loaded from YAML files.
 * 
 * Custom sections are stored as an ordered vector to preserve
 * the sequence from the YAML file, which affects rule application
 * order in iptables. Chain definitions are extracted separately
 * for dependency resolution during rule generation.
 */
struct Config {
    std::optional<FilterConfig> filter;  ///< Filter table configuration and policies
    std::vector<std::pair<std::string, SectionConfig>> custom_sections;  ///< Ordered custom sections
    std::map<std::string, ChainConfig> chain_definitions;  ///< Extracted chain definitions for dependency resolution

    /**
     * @brief Validate the complete configuration
     * @return true if all sections, filters, and chains are valid
     * 
     * Performs comprehensive validation including:
     * - Individual rule validation
     * - Chain reference validation
     * - Circular dependency detection
     * - Configuration consistency checks
     */
    bool isValid() const;
    
    /**
     * @brief Get detailed error message for invalid configurations
     * @return Human-readable error description or empty string if valid
     * 
     * Provides detailed information about configuration errors,
     * including the specific section and rule that failed validation.
     */
    std::string getErrorMessage() const;
};

}  // namespace iptables

/**
 * @namespace YAML
 * @brief YAML serialization template specializations
 * 
 * Contains template specializations for yaml-cpp to enable automatic
 * serialization and deserialization of all iptables configuration
 * structures to/from YAML format.
 */
namespace YAML {

/**
 * @brief YAML conversion for Policy enum
 * 
 * Converts between Policy enum values and YAML string representations:
 * - Policy::Accept <-> "accept"
 * - Policy::Drop <-> "drop"  
 * - Policy::Reject <-> "reject"
 */
template<>
struct convert<iptables::Policy> {
    /**
     * @brief Encode Policy enum to YAML node
     * @param policy Policy enum value to encode
     * @return YAML node containing string representation
     */
    static Node encode(const iptables::Policy& policy);
    
    /**
     * @brief Decode YAML node to Policy enum
     * @param node YAML node containing policy string
     * @param policy Output policy enum value
     * @return true if conversion successful
     */
    static bool decode(const Node& node, iptables::Policy& policy);
};

/**
 * @brief YAML conversion for Direction enum
 * 
 * Converts between Direction enum values and YAML string representations:
 * - Direction::Input <-> "input"
 * - Direction::Output <-> "output"
 */
template<>
struct convert<iptables::Direction> {
    /**
     * @brief Encode Direction enum to YAML node
     * @param direction Direction enum value to encode
     * @return YAML node containing string representation
     */
    static Node encode(const iptables::Direction& direction);
    
    /**
     * @brief Decode YAML node to Direction enum
     * @param node YAML node containing direction string
     * @param direction Output direction enum value
     * @return true if conversion successful
     */
    static bool decode(const Node& node, iptables::Direction& direction);
};

/**
 * @brief YAML conversion for Protocol enum
 * 
 * Converts between Protocol enum values and YAML string representations:
 * - Protocol::Tcp <-> "tcp"
 * - Protocol::Udp <-> "udp"
 */
template<>
struct convert<iptables::Protocol> {
    /**
     * @brief Encode Protocol enum to YAML node
     * @param protocol Protocol enum value to encode
     * @return YAML node containing string representation
     */
    static Node encode(const iptables::Protocol& protocol);
    
    /**
     * @brief Decode YAML node to Protocol enum
     * @param node YAML node containing protocol string
     * @param protocol Output protocol enum value
     * @return true if conversion successful
     */
    static bool decode(const Node& node, iptables::Protocol& protocol);
};

/**
 * @brief YAML conversion for Action enum
 * 
 * Converts between Action enum values and YAML string representations:
 * - Action::Accept <-> "accept"
 * - Action::Drop <-> "drop"
 * - Action::Reject <-> "reject"
 */
template<>
struct convert<iptables::Action> {
    /**
     * @brief Encode Action enum to YAML node
     * @param action Action enum value to encode
     * @return YAML node containing string representation
     */
    static Node encode(const iptables::Action& action);
    
    /**
     * @brief Decode YAML node to Action enum
     * @param node YAML node containing action string
     * @param action Output action enum value
     * @return true if conversion successful
     */
    static bool decode(const Node& node, iptables::Action& action);
};

/**
 * @brief YAML conversion for InterfaceConfig struct
 * 
 * Handles serialization of interface configuration including
 * input/output interface names and chain specifications.
 */
template<>
struct convert<iptables::InterfaceConfig> {
    /**
     * @brief Encode InterfaceConfig to YAML node
     * @param interface Interface configuration to encode
     * @return YAML node containing interface configuration
     */
    static Node encode(const iptables::InterfaceConfig& interface);
    
    /**
     * @brief Decode YAML node to InterfaceConfig
     * @param node YAML node containing interface configuration
     * @param interface Output interface configuration
     * @return true if conversion successful
     */
    static bool decode(const Node& node, iptables::InterfaceConfig& interface);
};

/**
 * @brief YAML conversion for PortConfig struct
 * 
 * Handles complex port configuration serialization including
 * single ports, port ranges, protocols, and related settings.
 */
template<>
struct convert<iptables::PortConfig> {
    /**
     * @brief Encode PortConfig to YAML node
     * @param config Port configuration to encode
     * @return YAML node containing port configuration
     */
    static Node encode(const iptables::PortConfig& config);
    
    /**
     * @brief Decode YAML node to PortConfig
     * @param node YAML node containing port configuration
     * @param config Output port configuration
     * @return true if conversion successful
     */
    static bool decode(const Node& node, iptables::PortConfig& config);
};

/**
 * @brief YAML conversion for MacConfig struct
 * 
 * Handles MAC address rule configuration serialization.
 */
template<>
struct convert<iptables::MacConfig> {
    /**
     * @brief Encode MacConfig to YAML node
     * @param config MAC configuration to encode
     * @return YAML node containing MAC configuration
     */
    static Node encode(const iptables::MacConfig& config);
    
    /**
     * @brief Decode YAML node to MacConfig
     * @param node YAML node containing MAC configuration
     * @param config Output MAC configuration
     * @return true if conversion successful
     */
    static bool decode(const Node& node, iptables::MacConfig& config);
};

/**
 * @brief YAML conversion for InterfaceRuleConfig struct
 * 
 * Handles interface rule configuration serialization.
 */
template<>
struct convert<iptables::InterfaceRuleConfig> {
    /**
     * @brief Encode InterfaceRuleConfig to YAML node
     * @param config Interface rule configuration to encode
     * @return YAML node containing interface rule configuration
     */
    static Node encode(const iptables::InterfaceRuleConfig& config);
    
    /**
     * @brief Decode YAML node to InterfaceRuleConfig
     * @param node YAML node containing interface rule configuration
     * @param config Output interface rule configuration
     * @return true if conversion successful
     */
    static bool decode(const Node& node, iptables::InterfaceRuleConfig& config);
};

/**
 * @brief YAML conversion for ChainRuleConfig struct
 * 
 * Handles custom chain rule configuration serialization.
 */
template<>
struct convert<iptables::ChainRuleConfig> {
    /**
     * @brief Encode ChainRuleConfig to YAML node
     * @param config Chain rule configuration to encode
     * @return YAML node containing chain rule configuration
     */
    static Node encode(const iptables::ChainRuleConfig& config);
    
    /**
     * @brief Decode YAML node to ChainRuleConfig
     * @param node YAML node containing chain rule configuration
     * @param config Output chain rule configuration
     * @return true if conversion successful
     */
    static bool decode(const Node& node, iptables::ChainRuleConfig& config);
};

/**
 * @brief YAML conversion for ChainConfig struct
 * 
 * Handles chain configuration container serialization.
 */
template<>
struct convert<iptables::ChainConfig> {
    /**
     * @brief Encode ChainConfig to YAML node
     * @param config Chain configuration to encode
     * @return YAML node containing chain configuration
     */
    static Node encode(const iptables::ChainConfig& config);
    
    /**
     * @brief Decode YAML node to ChainConfig
     * @param node YAML node containing chain configuration
     * @param config Output chain configuration
     * @return true if conversion successful
     */
    static bool decode(const Node& node, iptables::ChainConfig& config);
};

/**
 * @brief YAML conversion for FilterConfig struct
 * 
 * Handles filter table configuration serialization including
 * default policies and global MAC rules.
 */
template<>
struct convert<iptables::FilterConfig> {
    /**
     * @brief Encode FilterConfig to YAML node
     * @param config Filter configuration to encode
     * @return YAML node containing filter configuration
     */
    static Node encode(const iptables::FilterConfig& config);
    
    /**
     * @brief Decode YAML node to FilterConfig
     * @param node YAML node containing filter configuration
     * @param config Output filter configuration
     * @return true if conversion successful
     */
    static bool decode(const Node& node, iptables::FilterConfig& config);
};

/**
 * @brief YAML conversion for SectionConfig struct
 * 
 * Handles complex section configuration serialization including
 * all rule types and nested configurations.
 */
template<>
struct convert<iptables::SectionConfig> {
    /**
     * @brief Encode SectionConfig to YAML node
     * @param config Section configuration to encode
     * @return YAML node containing section configuration
     */
    static Node encode(const iptables::SectionConfig& config);
    
    /**
     * @brief Decode YAML node to SectionConfig
     * @param node YAML node containing section configuration
     * @param config Output section configuration
     * @return true if conversion successful
     */
    static bool decode(const Node& node, iptables::SectionConfig& config);
};

/**
 * @brief YAML conversion for Config struct
 * 
 * Handles root configuration serialization including filter
 * settings, custom sections, and chain definitions.
 */
template<>
struct convert<iptables::Config> {
    /**
     * @brief Encode Config to YAML node
     * @param config Root configuration to encode
     * @return YAML node containing complete configuration
     */
    static Node encode(const iptables::Config& config);
    
    /**
     * @brief Decode YAML node to Config
     * @param node YAML node containing complete configuration
     * @param config Output root configuration
     * @return true if conversion successful
     */
    static bool decode(const Node& node, iptables::Config& config);
};

}  // namespace YAML