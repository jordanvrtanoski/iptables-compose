#include "mac_rule.hpp"
#include <stdexcept>
#include <sstream>
#include <regex>

namespace iptables {

MacRule::MacRule(const std::string& mac_source,
                 Direction direction,
                 Action action,
                 const InterfaceConfig& interface,
                 const std::vector<std::string>& subnets,
                 const std::string& section_name,
                 const std::optional<std::string>& target_chain)
    : Rule(direction, action, interface, subnets, target_chain)
    , mac_source_(mac_source)
    , section_name_(section_name) {
    // MAC rules provide hardware address-based filtering for network access control
    // They are limited to INPUT direction due to iptables MAC module constraints
    // MAC filtering is only effective within the same broadcast domain (local network)
    
    // Enforce INPUT direction constraint for MAC rules
    // The iptables MAC module can only match source MAC addresses in the INPUT chain
    // This is because MAC addresses are only visible in the local network segment
    if (direction != Direction::Input) {
        throw std::invalid_argument("MAC filtering is only supported for INPUT direction due to hardware access limitations");
    }
    
    // Validate that only input interface is specified for MAC rules
    if (interface_.output.has_value()) {
        throw std::invalid_argument("MAC rules only support input interface specification");
    }
}

bool MacRule::isValid() const {
    // Perform comprehensive validation of MAC rule configuration
    // MAC rules have specific constraints due to the nature of MAC address filtering
    
    // First validate base rule properties (interfaces, subnets, chain names)
    if (!Rule::isValid()) {
        return false;  // Base validation failed
    }
    
    // Enforce INPUT direction constraint
    // MAC address filtering is only meaningful for incoming packets
    // Outgoing packets don't carry meaningful source MAC information for filtering
    if (direction_ != Direction::Input) {
        return false;  // MAC filtering only works on INPUT chain
    }
    
    // Validate MAC address format using regex pattern
    // Standard MAC format: XX:XX:XX:XX:XX:XX (hexadecimal octets separated by colons)
    // This ensures the MAC address can be properly processed by iptables
    std::regex mac_pattern("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$");
    if (!std::regex_match(mac_source_, mac_pattern)) {
        return false;  // Invalid MAC address format
    }
    
    // All validation checks passed
    return true;
}

std::string MacRule::getValidationError() const {
    // Provide detailed validation error messages for MAC rule troubleshooting
    // This helps users understand the specific constraints of MAC-based filtering
    
    // Check base class validation first and propagate any errors
    std::string base_error = Rule::getValidationError();
    if (!base_error.empty()) {
        return base_error;  // Return base validation error
    }
    
    // Check direction constraint specific to MAC rules
    if (direction_ != Direction::Input) {
        return "MAC filtering is only supported for INPUT direction. "
               "This limitation exists because MAC addresses are only available "
               "for packets entering the system from the local network segment. "
               "OUTPUT and FORWARD chains process packets after routing decisions, "
               "where original MAC information may not be preserved.";
    }
    
    // Validate MAC address format and provide specific guidance
    std::regex mac_pattern("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$");
    if (!std::regex_match(mac_source_, mac_pattern)) {
        return "Invalid MAC address format. Expected format: XX:XX:XX:XX:XX:XX";
    }
    
    // No validation errors found
    return "";
}

std::string MacRule::getComment() const {
    // Generate standardized comment for MAC rule identification and management
    // Comment format includes MAC address for easy identification during rule management
    
    // Create details string with MAC address information
    // This helps distinguish MAC rules from port-based rules in rule listings
    std::string details = "mac:" + mac_source_;
    
    // Use standard YAML comment format with MAC-specific details
    // The "any" parameter represents that MAC rules don't have additional MAC filtering
    // (since the MAC address is the primary filter criterion)
    return buildYamlComment(section_name_, "mac", details, "any");
}

std::vector<std::string> MacRule::buildIptablesCommand() const {
    std::vector<std::string> args;
    
    // Build MAC filtering rule for the INPUT chain
    // MAC rules are always applied to the INPUT chain due to iptables limitations
    args.push_back("-A");           // Append rule to chain
    args.push_back("INPUT");        // Always use INPUT chain for MAC filtering
    
    // Add interface filtering arguments if specified
    // Interface restrictions can limit MAC filtering to specific network interfaces
    // This is useful when different interfaces have different security requirements
    addInterfaceArgs(args);
    
    // Add subnet filtering arguments if specified
    // Subnet filtering can be combined with MAC filtering for additional security
    // This allows MAC-based rules to be restricted to specific network ranges
    addSubnetArgs(args);
    
    // Add MAC address matching module and source MAC filter
    // The MAC module provides hardware address-based packet matching
    // This is the core functionality that distinguishes MAC rules from other rule types
    args.push_back("-m");               // Load match module
    args.push_back("mac");              // MAC address matching module
    args.push_back("--mac-source");     // Match source MAC address
    args.push_back(mac_source_);        // Specific MAC address to match
    
    // Add the target action (ACCEPT, DROP, REJECT) or chain jump
    // This determines what happens to packets from the specified MAC address
    addTargetArgs(args);
    
    // Add identification comment for rule management
    // Comments enable the application to identify and manage its MAC rules
    addCommentArgs(args, getComment());
    
    return args;
}

bool MacRule::matches(const std::string& comment) const {
    // Implement flexible comment matching for MAC rule identification
    // This supports both current and legacy comment formats for rule management
    
    // Primary matching: use current comment format
    // This is the preferred method for newly created MAC rules
    std::string expected_comment = getComment();
    bool primary_match = comment.find(expected_comment) != std::string::npos;
    
    // Fallback matching: support legacy YAML comment format
    // Format: "YAML:section_name:mac:mac:mac_address"
    // This ensures compatibility with MAC rules created by older versions
    std::string legacy_pattern = "YAML:" + section_name_ + ":mac:mac:" + mac_source_;
    bool legacy_match = comment.find(legacy_pattern) != std::string::npos;
    
    // Return true if either matching method succeeds
    // This provides robust MAC rule identification across different comment formats
    return primary_match || legacy_match;
}

} // namespace iptables 