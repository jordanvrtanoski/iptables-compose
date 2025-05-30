#ifndef RULE_VALIDATOR_HPP
#define RULE_VALIDATOR_HPP

#include "config.hpp"
#include <string>
#include <vector>
#include <optional>

namespace iptables {

// Structure to represent a rule's selectivity for comparison
struct RuleSelectivity {
    // Network selectivity
    std::optional<std::vector<std::string>> subnets;  // More specific subnets = more selective
    
    // Port selectivity  
    std::optional<int> port;                     // Specific port = more selective
    Protocol protocol;                                // Specific protocol = more selective
    
    // Interface selectivity
    std::optional<std::string> input_interface;       // Specific interface = more selective
    std::optional<std::string> output_interface;      // Specific interface = more selective
    
    // MAC selectivity
    std::optional<std::string> mac_source;            // Specific MAC = more selective
    
    // Action
    bool allow;                                       // Action for this rule
    
    // Source information for error reporting
    std::string section_name;
    std::string rule_description;
    size_t rule_index;
};

// Structure to represent a validation warning
struct ValidationWarning {
    enum class Type {
        UnreachableRule,        // Rule will never be executed
        RedundantRule,          // Rule has same effect as earlier rule
        SubnetOverlap           // Rules have overlapping subnet conditions
    };
    
    Type type;
    std::string message;
    std::string section_name;
    size_t rule_index;
    
    // For conflicts between rules
    std::optional<std::string> conflicting_section;
    std::optional<size_t> conflicting_rule_index;
};

class RuleValidator {
public:
    /**
     * Validate rule order for potential conflicts
     * @param config The complete configuration to validate
     * @return Vector of validation warnings
     */
    static std::vector<ValidationWarning> validateRuleOrder(const Config& config);
    
    /**
     * Check if rule A makes rule B unreachable
     * @param rule_a The earlier rule in the chain
     * @param rule_b The later rule in the chain  
     * @return true if rule_a makes rule_b unreachable
     */
    static bool isRuleUnreachable(const RuleSelectivity& rule_a, const RuleSelectivity& rule_b);
    
    /**
     * Check if subnet A contains subnet B (A is less specific than B)
     * @param subnet_a The potentially containing subnet
     * @param subnet_b The potentially contained subnet
     * @return true if subnet_a contains subnet_b
     */
    static bool subnetContains(const std::string& subnet_a, const std::string& subnet_b);
    
    /**
     * Convert configuration rules to selectivity objects for analysis
     */
    static std::vector<RuleSelectivity> extractRuleSelectivity(const Config& config);
    
private:
    /**
     * Extract selectivity from a port configuration
     */
    static RuleSelectivity extractPortSelectivity(const PortConfig& port, const std::string& section, size_t index);
    
    /**
     * Extract selectivity from a MAC configuration  
     */
    static RuleSelectivity extractMacSelectivity(const MacConfig& mac, const std::string& section, size_t index);
    
    /**
     * Parse CIDR notation to get network address and prefix length
     */
    static std::pair<uint32_t, int> parseCIDR(const std::string& cidr);
    
    /**
     * Check if one interface specification is more specific than another
     */
    static bool isInterfaceMoreSpecific(const std::optional<std::string>& specific, 
                                       const std::optional<std::string>& general);
};

} // namespace iptables

#endif // RULE_VALIDATOR_HPP 