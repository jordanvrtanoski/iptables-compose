/**
 * @file rule_validator.hpp
 * @brief Advanced rule validation and analysis for iptables configurations
 * @author iptables-compose-cpp Development Team
 * @date 2024
 * 
 * This file contains comprehensive validation systems for analyzing iptables
 * rule configurations to detect conflicts, unreachable rules, circular
 * dependencies, and other potential issues. It provides static analysis
 * capabilities to ensure firewall configurations are logically consistent
 * and will behave as expected when applied.
 */

#ifndef RULE_VALIDATOR_HPP
#define RULE_VALIDATOR_HPP

#include "config.hpp"
#include <string>
#include <vector>
#include <optional>
#include <map>
#include <set>

namespace iptables {

/**
 * @struct RuleSelectivity
 * @brief Represents a rule's selectivity characteristics for conflict analysis
 * 
 * This structure extracts and normalizes the key characteristics of iptables
 * rules that determine their selectivity and potential for conflicts. It's
 * used for comparing rules to detect unreachable conditions, redundancy,
 * and overlapping coverage.
 * 
 * More selective rules (those with more specific conditions) should generally
 * appear before less selective rules to ensure proper packet matching.
 */
struct RuleSelectivity {
    std::optional<std::vector<std::string>> subnets;  ///< Network subnets (more specific = more selective)
    std::optional<int> port;                          ///< Specific single port (more selective than ranges)
    std::optional<std::vector<std::string>> port_ranges; ///< Port ranges using multiport extension
    Protocol protocol;                                ///< Network protocol (TCP/UDP specificity)
    std::optional<std::string> input_interface;       ///< Input interface specification
    std::optional<std::string> output_interface;      ///< Output interface specification
    std::optional<std::string> mac_source;            ///< MAC address source filter
    bool allow;                                       ///< Rule action (ACCEPT vs DROP/REJECT)
    std::optional<std::string> target_chain;         ///< Custom chain target instead of direct action
    
    // Source information for error reporting
    std::string section_name;     ///< Configuration section containing this rule
    std::string rule_description; ///< Human-readable rule description
    size_t rule_index;           ///< Index within the section for identification
};

/**
 * @struct ValidationWarning
 * @brief Represents a validation issue found during rule analysis
 * 
 * ValidationWarning encapsulates different types of issues that can be
 * detected in iptables configurations. These range from logical errors
 * (like unreachable rules) to potential efficiency problems (like
 * redundant rules) to configuration errors (like invalid chain references).
 */
struct ValidationWarning {
    /**
     * @enum Type
     * @brief Categories of validation issues
     * 
     * Defines the different types of validation problems that can be
     * detected during configuration analysis:
     */
    enum class Type {
        UnreachableRule,        ///< Rule will never be executed due to earlier rules
        RedundantRule,          ///< Rule has same effect as an earlier rule
        SubnetOverlap,          ///< Rules have overlapping subnet conditions
        ChainActionConflict,    ///< Both chain target and action specified (invalid)
        InvalidChainReference,  ///< Referenced chain does not exist in configuration
        CircularChainDependency ///< Circular dependency detected in chain calls
    };
    
    Type type;                          ///< Type of validation issue
    std::string message;                ///< Human-readable description of the issue
    std::string section_name;           ///< Section containing the problematic rule
    size_t rule_index;                 ///< Index of the rule within its section
    
    // For conflicts between multiple rules
    std::optional<std::string> conflicting_section;    ///< Section of the conflicting rule
    std::optional<size_t> conflicting_rule_index;     ///< Index of the conflicting rule
};

/**
 * @class RuleValidator
 * @brief Advanced static analysis engine for iptables rule validation
 * 
 * The RuleValidator class provides comprehensive static analysis capabilities
 * for iptables configurations. It can detect a wide range of issues including:
 * 
 * - Unreachable rules that will never execute due to earlier matches
 * - Redundant rules that duplicate the effect of previous rules  
 * - Overlapping subnet conditions that may cause unexpected behavior
 * - Invalid chain references to non-existent custom chains
 * - Circular dependencies in chain call hierarchies
 * - Mutual exclusivity violations (chain vs action specifications)
 * 
 * All validation methods are static and operate on complete Config objects
 * to provide comprehensive cross-rule and cross-section analysis.
 */
class RuleValidator {
public:
    /**
     * @brief Validate rule ordering for potential conflicts and issues
     * @param config The complete configuration to validate
     * @return Vector of validation warnings for ordering issues
     * 
     * Performs comprehensive analysis of rule ordering within and across
     * sections to detect unreachable rules, redundant conditions, and
     * subnet overlaps. Rules are analyzed in their application order
     * to ensure logical consistency.
     */
    static std::vector<ValidationWarning> validateRuleOrder(const Config& config);
    
    /**
     * @brief Validate chain configurations and references
     * @param config The complete configuration to validate
     * @return Vector of validation warnings for chain-related issues
     * 
     * Validates all chain references in the configuration including:
     * - Ensuring referenced chains exist in the configuration
     * - Detecting circular dependencies between chains
     * - Validating chain definition syntax and structure
     * - Checking for orphaned chain definitions
     */
    static std::vector<ValidationWarning> validateChainReferences(const Config& config);
    
    /**
     * @brief Validate port configuration for chain vs action conflicts
     * @param port_config Port configuration to validate
     * @param section_name Section name for error reporting
     * @param rule_index Rule index for error reporting
     * @return Validation warning if conflict found, empty optional otherwise
     * 
     * Checks for mutual exclusivity violations where both a chain target
     * and action (allow/forward) are specified in the same port rule.
     * These are logically inconsistent and will cause rule generation errors.
     */
    static std::optional<ValidationWarning> validatePortConfigChains(
        const PortConfig& port_config, 
        const std::string& section_name, 
        size_t rule_index);
    
    /**
     * @brief Validate MAC configuration for chain vs action conflicts
     * @param mac_config MAC configuration to validate
     * @param section_name Section name for error reporting
     * @param rule_index Rule index for error reporting
     * @return Validation warning if conflict found, empty optional otherwise
     * 
     * Checks for mutual exclusivity violations where both a chain target
     * and action (allow) are specified in the same MAC rule.
     * These are logically inconsistent and will cause rule generation errors.
     */
    static std::optional<ValidationWarning> validateMacConfigChains(
        const MacConfig& mac_config, 
        const std::string& section_name, 
        size_t rule_index);
    
    /**
     * @brief Check for circular dependencies in chain references
     * @param config The complete configuration to check
     * @return true if circular dependencies exist
     * 
     * Analyzes the complete chain dependency graph to detect cycles
     * that would cause infinite loops or undefined behavior when
     * rules are applied. Uses depth-first search for cycle detection.
     */
    static bool hasCircularChainDependencies(const Config& config);
    
    /**
     * @brief Determine if one rule makes another unreachable
     * @param rule_a The earlier rule in the chain
     * @param rule_b The later rule in the chain  
     * @return true if rule_a completely shadows rule_b
     * 
     * Analyzes two rules to determine if the first rule's conditions
     * completely encompass the second rule's conditions with the same
     * or broader scope. If so, the second rule will never be executed.
     */
    static bool isRuleUnreachable(const RuleSelectivity& rule_a, const RuleSelectivity& rule_b);
    
    /**
     * @brief Check if one subnet contains another subnet
     * @param subnet_a The potentially containing subnet (CIDR notation)
     * @param subnet_b The potentially contained subnet (CIDR notation)
     * @return true if subnet_a completely contains subnet_b
     * 
     * Performs CIDR analysis to determine if subnet A completely
     * contains subnet B (A is less specific than B). Used for
     * detecting subnet-based rule conflicts and overlaps.
     */
    static bool subnetContains(const std::string& subnet_a, const std::string& subnet_b);
    
    /**
     * @brief Extract rule selectivity information from configuration
     * @param config The configuration to analyze
     * @return Vector of RuleSelectivity objects for all rules
     * 
     * Converts all rules in the configuration into normalized
     * RuleSelectivity objects for analysis. This includes extracting
     * selectivity from port rules, MAC rules, and other rule types
     * across all sections.
     */
    static std::vector<RuleSelectivity> extractRuleSelectivity(const Config& config);
    
private:
    /**
     * @brief Extract selectivity characteristics from a port configuration
     * @param port Port configuration to analyze
     * @param section Section name containing the rule
     * @param index Rule index within the section
     * @return RuleSelectivity object representing the port rule
     * 
     * Analyzes a PortConfig and extracts its selectivity characteristics
     * including port numbers/ranges, protocol, interfaces, subnets,
     * and action/chain information.
     */
    static RuleSelectivity extractPortSelectivity(const PortConfig& port, const std::string& section, size_t index);
    
    /**
     * @brief Extract selectivity characteristics from a MAC configuration
     * @param mac MAC configuration to analyze
     * @param section Section name containing the rule
     * @param index Rule index within the section
     * @return RuleSelectivity object representing the MAC rule
     * 
     * Analyzes a MacConfig and extracts its selectivity characteristics
     * including MAC addresses, interfaces, subnets, and action/chain
     * information.
     */
    static RuleSelectivity extractMacSelectivity(const MacConfig& mac, const std::string& section, size_t index);
    
    /**
     * @brief Build dependency graph for chain references
     * @param config The configuration to analyze
     * @return Map of chain names to sets of chains they depend on
     * 
     * Constructs a directed graph representing dependencies between
     * custom chains. Each chain maps to the set of other chains it
     * references or calls. Used for circular dependency detection.
     */
    static std::map<std::string, std::set<std::string>> buildChainDependencyGraph(const Config& config);
    
    /**
     * @brief Detect cycles in a dependency graph using depth-first search
     * @param graph The dependency graph to analyze
     * @return true if any cycles are detected
     * 
     * Implements cycle detection using DFS with color-based tracking.
     * Detects any circular dependencies that would cause infinite
     * loops in chain execution.
     */
    static bool hasCycleInGraph(const std::map<std::string, std::set<std::string>>& graph);
    
    /**
     * @brief Parse CIDR notation into network address and prefix length
     * @param cidr CIDR string (e.g., "192.168.1.0/24")
     * @return Pair of network address (as uint32_t) and prefix length
     * @throws std::invalid_argument if CIDR format is invalid
     * 
     * Parses CIDR notation strings into binary network addresses and
     * prefix lengths for mathematical subnet containment analysis.
     */
    static std::pair<uint32_t, int> parseCIDR(const std::string& cidr);
    
    /**
     * @brief Check if one interface specification is more specific than another
     * @param specific The potentially more specific interface specification
     * @param general The potentially more general interface specification
     * @return true if specific is more restrictive than general
     * 
     * Compares interface specifications to determine relative selectivity.
     * More specific interface conditions make rules more selective and
     * should generally appear earlier in rule chains.
     */
    static bool isInterfaceMoreSpecific(const std::optional<std::string>& specific, 
                                       const std::optional<std::string>& general);
};

} // namespace iptables

#endif // RULE_VALIDATOR_HPP 