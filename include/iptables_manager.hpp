/**
 * @file iptables_manager.hpp
 * @brief Main orchestration class for iptables rule management
 * @author iptables-compose-cpp Development Team
 * @date 2024
 * 
 * This file contains the IptablesManager class, which serves as the primary
 * orchestrator for iptables operations in the iptables-compose-cpp system.
 * It coordinates configuration loading, rule processing, chain management,
 * and policy setting to provide a comprehensive firewall management interface.
 */

#pragma once

#include "rule_manager.hpp"
#include "chain_manager.hpp"
#include "command_executor.hpp"
#include "config.hpp"
#include <string>
#include <filesystem>
#include <yaml-cpp/yaml.h>

namespace iptables {

/**
 * @class IptablesManager
 * @brief Main orchestration class for comprehensive iptables management
 * 
 * The IptablesManager class serves as the central coordinator for all iptables
 * operations within the iptables-compose-cpp system. It provides a high-level
 * interface that abstracts the complexity of iptables rule management while
 * ensuring proper ordering, dependency resolution, and error handling.
 * 
 * Key responsibilities include:
 * - Loading and validating YAML configuration files
 * - Processing configuration into iptables rules and chains
 * - Coordinating rule application with proper dependency ordering
 * - Managing custom chain creation and cross-chain references
 * - Setting filter table policies for built-in chains
 * - Providing cleanup and reset functionality
 * - Orchestrating rule removal and firewall restoration
 * 
 * The class integrates with RuleManager for individual rule operations,
 * ChainManager for custom chain handling, and CommandExecutor for
 * low-level iptables command execution.
 */
class IptablesManager {
public:
    /**
     * @brief Construct a new IptablesManager instance
     * 
     * Initializes all internal managers and prepares the system for
     * iptables operations. Does not perform any iptables commands
     * during construction.
     */
    IptablesManager();
    
    /**
     * @brief Destructor
     * 
     * Cleans up resources. Does not automatically remove iptables
     * rules - use removeAllRules() explicitly if needed.
     */
    ~IptablesManager() = default;

    // Configuration management
    
    /**
     * @brief Load configuration from a YAML file
     * @param config_path Path to the YAML configuration file
     * @return true if configuration was loaded and validated successfully
     * @throws std::filesystem::filesystem_error if file cannot be accessed
     * @throws YAML::Exception if YAML parsing fails
     * 
     * Loads, parses, and validates a complete iptables configuration from
     * a YAML file. This includes all sections, rules, chains, and policies.
     * The configuration is validated for consistency and correctness before
     * being accepted. Does not apply rules - use applyRules() separately.
     */
    bool loadConfig(const std::filesystem::path& config_path);
    
    /**
     * @brief Reset all iptables rules to default state
     * @return true if reset was successful
     * 
     * Removes all custom rules and chains, then sets all built-in chain
     * policies to ACCEPT. This provides a clean slate for rule application
     * or system restoration. Equivalent to running iptables flush and
     * policy reset commands.
     */
    bool resetRules();
    
    /**
     * @brief Remove rules created from YAML configuration
     * @return true if removal was successful
     * 
     * Selectively removes only the rules and chains that were created
     * from the loaded YAML configuration, leaving other iptables rules
     * intact. This is useful for updating configurations without
     * affecting unrelated firewall rules.
     */
    bool removeYamlRules();

    // Rule management
    
    /**
     * @brief Apply all rules from the loaded configuration
     * @return true if all rules were applied successfully
     * @throws std::runtime_error if no configuration is loaded
     * 
     * Processes the loaded configuration and applies all rules, chains,
     * and policies to iptables in the correct order. This includes:
     * - Creating custom chains with proper dependencies
     * - Processing filter policies for built-in chains
     * - Applying port, MAC, and interface rules
     * - Setting up chain cross-references and jumps
     * 
     * If any rule fails to apply, the process stops and returns false.
     */
    bool applyRules();
    
    /**
     * @brief Remove all iptables rules and chains
     * @return true if removal was successful
     * 
     * Removes all rules from all chains, deletes all custom chains,
     * and resets built-in chain policies to ACCEPT. This is a complete
     * firewall cleanup that removes both YAML-managed and external rules.
     */
    bool removeAllRules();

    // Policy management
    
    /**
     * @brief Set default policy for a built-in chain
     * @param direction Chain direction (INPUT or OUTPUT)
     * @param action Policy action (ACCEPT, DROP, or REJECT)
     * @return true if policy was set successfully
     * @throws std::invalid_argument if direction or action is invalid
     * 
     * Sets the default policy for INPUT or OUTPUT chains in the filter
     * table. The policy determines what happens to packets that don't
     * match any rules in the chain. FORWARD chain policies should be
     * managed through the configuration file.
     */
    bool setPolicy(Direction direction, Action action);
    
    /**
     * @brief Reset all built-in chain policies to ACCEPT
     * @return true if policies were reset successfully
     * 
     * Sets the default policy for INPUT, OUTPUT, and FORWARD chains
     * to ACCEPT, providing a permissive default state. This is typically
     * done before rule removal to prevent lockouts.
     */
    bool resetPolicies();

private:
    RuleManager rule_manager_;      ///< Manages individual iptables rules
    CommandExecutor command_executor_;  ///< Executes low-level iptables commands
    ChainManager chain_manager_;    ///< Manages custom chain operations

    // Configuration processing
    
    /**
     * @brief Process filter configuration section
     * @param filter Filter configuration containing policies and MAC rules
     * @return true if filter configuration was processed successfully
     * 
     * Processes the filter section of the configuration, setting default
     * policies for built-in chains and applying global MAC filtering rules.
     */
    bool processFilterConfig(const FilterConfig& filter);
    
    /**
     * @brief Process a single port configuration rule
     * @param port Port configuration to process
     * @param section_name Name of the section containing this rule
     * @return true if port rule was processed successfully
     * 
     * Converts a PortConfig into appropriate iptables rules, handling
     * single ports, port ranges, forwarding, and multiport configurations.
     */
    bool processPortConfig(const PortConfig& port, const std::string& section_name);
    
    /**
     * @brief Process a single MAC configuration rule
     * @param mac MAC configuration to process
     * @param section_name Name of the section containing this rule
     * @return true if MAC rule was processed successfully
     * 
     * Converts a MacConfig into appropriate iptables rules for MAC
     * address filtering with support for interfaces and subnets.
     */
    bool processMacConfig(const MacConfig& mac, const std::string& section_name);
    
    /**
     * @brief Process a single interface configuration rule
     * @param interface Interface configuration to process
     * @param section_name Name of the section containing this rule
     * @return true if interface rule was processed successfully
     * 
     * Converts an InterfaceRuleConfig into appropriate iptables rules
     * for interface-based traffic control.
     */
    bool processInterfaceConfig(const InterfaceRuleConfig& interface, const std::string& section_name);
    
    /**
     * @brief Process an action configuration (catch-all rules)
     * @param action Action to apply for unmatched traffic
     * @param section_name Name of the section containing this action
     * @return true if action rule was processed successfully
     * 
     * Creates catch-all rules that apply the specified action to traffic
     * that doesn't match more specific rules in the section.
     */
    bool processActionConfig(const Action& action, const std::string& section_name);
    
    /**
     * @brief Process interface configuration for chain calls
     * @param interface Interface configuration specifying chain targets
     * @param section_name Name of the section containing this configuration
     * @return true if interface chain call was processed successfully
     * 
     * Creates rules that jump to custom chains based on interface
     * specifications, enabling modular firewall organization.
     */
    bool processInterfaceChainCall(const InterfaceConfig& interface, const std::string& section_name);
    
    // Chain configuration processing methods
    
    /**
     * @brief Create a custom iptables chain
     * @param chain_name Name of the chain to create
     * @return true if chain was created successfully
     * 
     * Creates a new custom chain in the filter table. Checks for
     * existing chains to avoid conflicts and validates chain names.
     */
    bool createChain(const std::string& chain_name);
    
    /**
     * @brief Process a complete chain configuration
     * @param chain_name Name of the chain being configured
     * @param chain_config Configuration containing multiple chain rules
     * @return true if chain configuration was processed successfully
     * 
     * Processes a ChainConfig containing multiple chain definitions,
     * creating chains and applying their associated rule sets.
     */
    bool processChainConfig(const std::string& chain_name, const ChainConfig& chain_config);
    
    /**
     * @brief Process a single chain rule configuration
     * @param chain_name Name of the target chain
     * @param chain_rule Configuration for a single chain
     * @return true if chain rule was processed successfully
     * 
     * Processes a ChainRuleConfig, creating the chain and applying
     * its default action and associated rule groups.
     */
    bool processChainRuleConfig(const std::string& chain_name, const ChainRuleConfig& chain_rule);
    
    /**
     * @brief Process rules within a custom chain
     * @param chain_name Name of the chain containing the rules
     * @param rules Map of section names to rule configurations
     * @return true if all chain rules were processed successfully
     * 
     * Processes all rule sections within a custom chain, maintaining
     * proper rule ordering and section organization.
     */
    bool processChainRules(const std::string& chain_name, const std::map<std::string, SectionConfig>& rules);

    // Configuration parsing (legacy methods)
    
    /**
     * @brief Parse filter configuration from YAML node (legacy)
     * @param node YAML node containing filter configuration
     * @return true if parsing was successful
     * @deprecated Use processFilterConfig with Config structures instead
     * 
     * Legacy method for parsing filter configuration directly from
     * YAML nodes. Maintained for backwards compatibility.
     */
    bool parseFilterConfig(const YAML::Node& node);
    
    /**
     * @brief Parse port configuration from YAML node (legacy)
     * @param node YAML node containing port configuration
     * @param section_name Name of the containing section
     * @return true if parsing was successful
     * @deprecated Use processPortConfig with PortConfig structures instead
     * 
     * Legacy method for parsing port configuration directly from
     * YAML nodes. Maintained for backwards compatibility.
     */
    bool parsePortConfig(const YAML::Node& node, const std::string& section_name);
    
    /**
     * @brief Parse MAC configuration from YAML node (legacy)
     * @param node YAML node containing MAC configuration
     * @param section_name Name of the containing section
     * @return true if parsing was successful
     * @deprecated Use processMacConfig with MacConfig structures instead
     * 
     * Legacy method for parsing MAC configuration directly from
     * YAML nodes. Maintained for backwards compatibility.
     */
    bool parseMacConfig(const YAML::Node& node, const std::string& section_name);
    
    // Helper methods
    
    /**
     * @brief Parse direction string to Direction enum
     * @param direction Direction string ("input" or "output")
     * @return Direction enum value
     * @throws std::invalid_argument if direction string is invalid
     * 
     * Converts string representations of directions to enum values
     * with case-insensitive matching and validation.
     */
    Direction parseDirection(const std::string& direction);
    
    /**
     * @brief Parse action string to Action enum
     * @param action Action string ("accept", "drop", or "reject")
     * @return Action enum value
     * @throws std::invalid_argument if action string is invalid
     * 
     * Converts string representations of actions to enum values
     * with case-insensitive matching and validation.
     */
    Action parseAction(const std::string& action);
    
    /**
     * @brief Parse protocol string to Protocol enum
     * @param protocol Protocol string ("tcp" or "udp")
     * @return Protocol enum value
     * @throws std::invalid_argument if protocol string is invalid
     * 
     * Converts string representations of protocols to enum values
     * with case-insensitive matching and validation.
     */
    Protocol parseProtocol(const std::string& protocol);
    
    /**
     * @brief Parse interface configuration from YAML node
     * @param node YAML node containing interface configuration
     * @return InterfaceConfig structure
     * @throws YAML::Exception if YAML structure is invalid
     * 
     * Parses interface configuration from YAML, handling both
     * simple string values and complex interface specifications.
     */
    InterfaceConfig parseInterface(const YAML::Node& node);
};

} // namespace iptables 