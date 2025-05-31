#include "tcp_rule.hpp"
#include <sstream>

namespace iptables {

TcpRule::TcpRule(uint16_t port, 
                 Direction direction,
                 Action action,
                 const InterfaceConfig& interface,
                 const std::vector<std::string>& subnets,
                 std::optional<std::string> mac_source,
                 std::optional<uint16_t> forward_port,
                 const std::string& section_name,
                 const std::optional<std::string>& target_chain)
    : Rule(direction, action, interface, subnets, target_chain)
    , port_(port)
    , mac_source_(std::move(mac_source))
    , forward_port_(forward_port)
    , section_name_(section_name) {
    // TCP rules handle port-based filtering and forwarding for TCP protocol
    // They support both simple port filtering (filter table) and port forwarding (nat table)
    // The rule configuration is validated in isValid() to ensure mutual exclusivity constraints
}

bool TcpRule::isValid() const {
    // Perform comprehensive validation of TCP rule configuration
    // This ensures the rule can be successfully applied to iptables
    
    // First validate base rule properties (interfaces, subnets, chain names)
    if (!Rule::isValid()) {
        return false;  // Base validation failed
    }
    
    // Enforce mutual exclusivity between port forwarding and chain targets
    // Port forwarding uses NAT table REDIRECT target, while chain targets use filter table jumps
    // These are incompatible configurations that would create conflicting iptables commands
    if (forward_port_.has_value() && target_chain_.has_value()) {
        return false;  // Cannot use both forwarding and chain targeting
    }
    
    // Validate primary port number range
    // Port 0 is reserved and ports above 65535 exceed the TCP/UDP port space
    // This validation prevents iptables errors and ensures meaningful rules
    if (port_ == 0 || port_ > 65535) {
        return false;  // Invalid primary port range
    }
    
    // Validate forwarding port number range if specified
    // Same constraints as primary port: must be in valid TCP/UDP range
    if (forward_port_.has_value() && (*forward_port_ == 0 || *forward_port_ > 65535)) {
        return false;  // Invalid forwarding port range
    }
    
    // All validation checks passed
    return true;
}

std::string TcpRule::getValidationError() const {
    // Provide detailed validation error messages for troubleshooting
    // This complements the boolean isValid() method with specific error descriptions
    
    // Check base class validation first and propagate any errors
    std::string base_error = Rule::getValidationError();
    if (!base_error.empty()) {
        return base_error;  // Return base validation error
    }
    
    // Check for mutual exclusivity violation between forwarding and chain targeting
    if (forward_port_.has_value() && target_chain_.has_value()) {
        return "Port forwarding cannot be used with chain targets";
    }
    
    // Validate primary port number and provide specific guidance
    if (port_ == 0 || port_ > 65535) {
        return "Port number must be between 1 and 65535";
    }
    
    // Validate forwarding port number if present
    if (forward_port_.has_value() && (*forward_port_ == 0 || *forward_port_ > 65535)) {
        return "Forward port number must be between 1 and 65535";
    }
    
    // No validation errors found
    return "";
}

std::string TcpRule::getComment() const {
    // Generate standardized comment for TCP rule identification and management
    // Comment format includes rule type, configuration details, and MAC information
    
    // Extract MAC address for comment, defaulting to "any" if not specified
    // This provides consistent comment formatting across different rule configurations
    std::string mac_comment = mac_source_.value_or("any");
    
    // Generate comment based on rule configuration type
    if (forward_port_) {
        // Port forwarding rule: include both source and destination ports
        // This helps identify forwarding rules during management operations
        std::string details = "port:" + std::to_string(port_) + ":forward:" + std::to_string(*forward_port_);
        return buildYamlComment(section_name_, "tcp", details, mac_comment);
    } else if (target_chain_.has_value()) {
        // Chain targeting rule: include port and target chain information
        // This distinguishes chain jumps from simple allow/deny rules
        std::string details = "port:" + std::to_string(port_) + ":chain:" + *target_chain_;
        return buildYamlComment(section_name_, "tcp", details, mac_comment);
    } else {
        // Simple port rule: include only the port number
        // This represents basic allow/deny rules without special routing
        std::string details = "port:" + std::to_string(port_);
        return buildYamlComment(section_name_, "tcp", details, mac_comment);
    }
}

std::vector<std::string> TcpRule::buildIptablesCommand() const {
    std::vector<std::string> args;
    
    // Check if this is a port forwarding rule and use specialized command construction
    // Port forwarding requires different iptables syntax (NAT table, REDIRECT target)
    if (forward_port_) {
        return buildPortForwardingCommand();
    }
    
    // Build standard TCP filter rule for the specified chain and direction
    // This handles normal TCP port filtering in the filter table
    args.push_back("-A");                    // Append rule to chain
    args.push_back(directionToString());     // Specify target chain based on direction
    
    // Specify TCP protocol for packet matching
    // This ensures the rule only matches TCP packets, not UDP or other protocols
    args.push_back("-p");
    args.push_back("tcp");
    
    // Add interface filtering arguments if specified
    // Interface restrictions limit rule scope to specific network interfaces
    addInterfaceArgs(args);
    
    // Add subnet filtering arguments if specified
    // Source/destination subnet filtering provides network-based access control
    addSubnetArgs(args);
    
    // Add MAC address filtering if specified
    // MAC filtering provides additional layer of access control based on hardware addresses
    // Note: MAC filtering is only effective for local network segments
    if (mac_source_.has_value()) {
        args.push_back("-m");               // Load match module
        args.push_back("mac");              // MAC address matching module
        args.push_back("--mac-source");     // Match source MAC address
        args.push_back(*mac_source_);       // Specific MAC address to match
    }
    
    // Add TCP destination port matching
    // --dport specifies the destination port for incoming connections
    args.push_back("--dport");
    args.push_back(std::to_string(port_));
    
    // Add the target action (ACCEPT, DROP, REJECT) or chain jump
    // This determines what happens to packets matching the rule criteria
    addTargetArgs(args);
    
    // Add identification comment for rule management
    // Comments enable the application to identify and manage its rules
    addCommentArgs(args, getComment());
    
    return args;
}

std::vector<std::string> TcpRule::buildPortForwardingCommand() const {
    std::vector<std::string> args;
    
    // Port forwarding uses the NAT table's PREROUTING chain
    // This intercepts packets before routing decisions and redirects them
    args.push_back("-t");           // Specify table
    args.push_back("nat");          // Network Address Translation table
    args.push_back("-A");           // Append rule
    args.push_back("PREROUTING");   // Pre-routing chain for incoming packets
    
    // Specify TCP protocol for the forwarding rule
    // Port forwarding can be protocol-specific (TCP vs UDP)
    args.push_back("-p");
    args.push_back("tcp");
    
    // Add input interface filtering if specified
    // Interface filtering for forwarding typically uses input interface only
    // Output interface is not meaningful in PREROUTING chain
    if (interface_.input.has_value()) {
        args.push_back("-i");
        args.push_back(*interface_.input);
    }
    
    // Add subnet filtering for forwarding rules
    // This allows forwarding to be restricted to specific source/destination networks
    addSubnetArgs(args);
    
    // Add MAC address filtering for forwarding if specified
    // MAC filtering can provide additional security for port forwarding
    if (mac_source_.has_value()) {
        args.push_back("-m");
        args.push_back("mac");
        args.push_back("--mac-source");
        args.push_back(*mac_source_);
    }
    
    // Match the original destination port
    // This is the port that incoming connections are trying to reach
    args.push_back("--dport");
    args.push_back(std::to_string(port_));
    
    // Use REDIRECT target to forward to a different port
    // REDIRECT changes the destination port while keeping the same host
    // This is simpler than DNAT and works well for local port forwarding
    args.push_back("-j");
    args.push_back("REDIRECT");
    args.push_back("--to-port");
    args.push_back(std::to_string(*forward_port_));
    
    // Add identification comment for forwarding rule management
    addCommentArgs(args, getComment());
    
    return args;
}

bool TcpRule::matches(const std::string& comment) const {
    // Implement flexible comment matching for TCP rule identification
    // This supports both current and legacy comment formats for rule management
    
    // Primary matching: use current comment format
    // This is the preferred method for newly created rules
    std::string expected_comment = getComment();
    bool primary_match = comment.find(expected_comment) != std::string::npos;
    
    // Fallback matching: support legacy YAML comment format
    // Format: "YAML:section_name:tcp:port:port_number"
    // This ensures compatibility with rules created by older versions
    std::string legacy_pattern = "YAML:" + section_name_ + ":tcp:port:" + std::to_string(port_);
    bool legacy_match = comment.find(legacy_pattern) != std::string::npos;
    
    // Return true if either matching method succeeds
    // This provides robust rule identification across different comment formats
    return primary_match || legacy_match;
}

} // namespace iptables 