/**
 * @file rule_manager.hpp
 * @brief Rule management and orchestration for iptables operations
 * @author iptables-compose-cpp Development Team
 * @date 2024
 * 
 * This file contains the RuleManager class, which provides comprehensive
 * management of iptables rules including creation, application, removal,
 * and querying. It serves as an intermediary between high-level configuration
 * and low-level iptables command execution.
 */

#pragma once

#include "rule.hpp"
#include "tcp_rule.hpp"
#include "udp_rule.hpp"
#include "mac_rule.hpp"
#include "chain_rule.hpp"
#include "command_executor.hpp"
#include <memory>
#include <vector>
#include <string>
#include <unordered_map>

namespace iptables {

/**
 * @class RuleManager
 * @brief Comprehensive manager for iptables rule operations and lifecycle
 * 
 * The RuleManager class provides a high-level interface for managing
 * collections of iptables rules. It handles rule storage, application,
 * removal, and querying while abstracting the complexity of iptables
 * command generation and execution.
 * 
 * Key capabilities include:
 * - Rule collection management with type-safe rule objects
 * - Batch rule application with proper ordering
 * - Selective rule removal by various criteria
 * - Policy management for built-in chains
 * - YAML configuration integration
 * - Rule querying and inspection
 * - Error handling and rollback operations
 * 
 * The manager maintains an internal collection of Rule objects and
 * coordinates with CommandExecutor for actual iptables operations.
 * It supports all rule types including TCP, UDP, MAC, and chain rules.
 */
class RuleManager {
public:
    /**
     * @brief Default constructor
     * 
     * Initializes an empty rule manager ready to accept and manage
     * iptables rules. No iptables operations are performed during
     * construction.
     */
    RuleManager() = default;
    
    /**
     * @brief Default destructor
     * 
     * Cleans up rule manager resources. Does not automatically
     * remove applied iptables rules - use removeAllRules() if needed.
     */
    ~RuleManager() = default;

    // Rule management
    
    /**
     * @brief Add a rule to the manager
     * @param rule Shared pointer to the rule object to add
     * @throws std::invalid_argument if rule is null
     * 
     * Adds a rule to the internal collection for later application.
     * The rule is validated during addition. Does not immediately
     * apply the rule to iptables - use applyRules() for that.
     */
    void addRule(std::shared_ptr<Rule> rule);
    
    /**
     * @brief Remove rules by comment identifier
     * @param comment Comment string used to identify rules to remove
     * 
     * Removes all rules from the internal collection that have the
     * specified comment. This affects the managed collection but
     * does not remove rules from iptables - use removeAllRules()
     * to clean up applied rules.
     */
    void removeRule(const std::string& comment);
    
    /**
     * @brief Clear all rules from the manager
     * 
     * Removes all rules from the internal collection. This does not
     * affect rules already applied to iptables - use removeAllRules()
     * for complete cleanup.
     */
    void clearRules();

    // Rule application
    
    /**
     * @brief Apply all managed rules to iptables
     * @return true if all rules were applied successfully
     * 
     * Applies all rules in the internal collection to iptables in
     * the correct order. If any rule fails to apply, the process
     * stops and returns false. Successfully applied rules remain
     * in iptables even if later rules fail.
     */
    bool applyRules();
    
    /**
     * @brief Remove all applied rules from iptables
     * @return true if all rules were removed successfully
     * 
     * Removes all rules that were applied by this manager from
     * iptables. This includes flushing chains and resetting
     * policies to safe defaults (ACCEPT).
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
     * Sets the default policy for INPUT or OUTPUT chains in the
     * filter table. The policy determines what happens to packets
     * that don't match any rules in the chain.
     */
    bool setPolicy(Direction direction, Action action);
    
    /**
     * @brief Reset all built-in chain policies to ACCEPT
     * @return true if policies were reset successfully
     * 
     * Sets the default policy for INPUT, OUTPUT, and FORWARD
     * chains to ACCEPT, providing a permissive default state.
     * This is typically done before rule removal to prevent lockouts.
     */
    bool resetPolicies();

    // Rule querying
    
    /**
     * @brief Get rules by comment identifier
     * @param comment Comment string to search for
     * @return Vector of rules matching the comment
     * 
     * Returns all rules in the managed collection that have the
     * specified comment. Useful for finding rules created from
     * specific configuration sections.
     */
    std::vector<std::shared_ptr<Rule>> getRulesByComment(const std::string& comment) const;
    
    /**
     * @brief Get rules by traffic direction
     * @param direction Traffic direction (INPUT or OUTPUT)
     * @return Vector of rules matching the direction
     * 
     * Returns all rules in the managed collection that apply to
     * the specified traffic direction. Useful for analyzing
     * directional rule coverage.
     */
    std::vector<std::shared_ptr<Rule>> getRulesByDirection(Direction direction) const;
    
    /**
     * @brief Get all managed rules
     * @return Vector containing all rules in the collection
     * 
     * Returns a copy of all rules currently managed by this
     * RuleManager instance. Useful for inspection and debugging.
     */
    std::vector<std::shared_ptr<Rule>> getAllRules() const;

    // Enhanced rule management for YAML compatibility
    
    /**
     * @brief Remove rules by signature from iptables
     * @param chain Target chain name
     * @param comment Comment identifier for rules
     * @param table Target table name (default: "filter")
     * @return true if rules were removed successfully
     * 
     * Removes specific rules from iptables based on chain, comment,
     * and table. This method queries iptables for matching rules
     * and removes them by line number. More precise than bulk removal.
     */
    bool removeRulesBySignature(const std::string& chain, 
                               const std::string& comment,
                               const std::string& table = "filter");
    
    /**
     * @brief Remove all YAML-generated rules from iptables
     * @return true if all YAML rules were removed successfully
     * 
     * Removes all rules that were generated from YAML configuration
     * by searching for specific comment patterns. Leaves manually
     * created iptables rules intact.
     */
    bool removeAllYamlRules();
    
    /**
     * @brief Reset all chain policies to default values
     * @return true if all policies were reset successfully
     * 
     * Resets the default policies for all built-in chains
     * (INPUT, OUTPUT, FORWARD) to ACCEPT. Provides a safe
     * default state for firewall operations.
     */
    bool resetAllPolicies();

private:
    std::vector<std::shared_ptr<Rule>> rules_;  ///< Collection of managed rules
    
    // Helper methods
    
    /**
     * @brief Execute an iptables command with error handling
     * @param args Command arguments for iptables
     * @return true if command executed successfully
     * 
     * Executes an iptables command using CommandExecutor and handles
     * errors appropriately. Provides logging and error reporting for
     * debugging purposes.
     */
    bool executeIptablesCommand(const std::vector<std::string>& args) const;
    
    /**
     * @brief Get line numbers of rules matching criteria
     * @param chain Target chain name
     * @param comment Comment identifier to search for
     * @param table Target table name (default: "filter")
     * @return Vector of line numbers for matching rules
     * 
     * Queries iptables for rules matching the specified criteria
     * and returns their line numbers. Used for precise rule removal
     * operations.
     */
    std::vector<uint32_t> getRuleLineNumbers(const std::string& chain, 
                                           const std::string& comment,
                                           const std::string& table = "filter") const;
    
    /**
     * @brief Convert direction enum to chain name
     * @param direction Direction enum value
     * @return Chain name string ("INPUT" or "OUTPUT")
     * 
     * Converts Direction enum values to the corresponding iptables
     * chain names for use in command generation.
     */
    std::string getChainName(Direction direction) const;
    
    /**
     * @brief Convert direction enum to string representation
     * @param direction Direction enum value
     * @return Direction string ("input" or "output")
     * 
     * Converts Direction enum values to lowercase string
     * representations for logging and display purposes.
     */
    std::string directionToString(Direction direction) const;
    
    /**
     * @brief Convert action enum to string representation
     * @param action Action enum value
     * @return Action string ("ACCEPT", "DROP", or "REJECT")
     * 
     * Converts Action enum values to uppercase string
     * representations suitable for iptables commands.
     */
    std::string actionToString(Action action) const;
};

} // namespace iptables 