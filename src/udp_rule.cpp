#include "udp_rule.hpp"
#include <sstream>

namespace iptables {

UdpRule::UdpRule(uint16_t port, 
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
    // UDP rules handle port-based filtering and forwarding for UDP protocol
    // UDP is connectionless, so forwarding behavior differs slightly from TCP
    // The rule configuration is validated in isValid() to ensure proper UDP semantics
}

bool UdpRule::isValid() const {
    // Perform comprehensive validation of UDP rule configuration
    // UDP rules share most validation logic with TCP but have protocol-specific considerations
    
    // First validate base rule properties (interfaces, subnets, chain names)
    if (!Rule::isValid()) {
        return false;  // Base validation failed
    }
    
    // Enforce mutual exclusivity between port forwarding and chain targets
    // This constraint applies to both TCP and UDP rules for consistency
    // Port forwarding uses NAT table while chain targets use filter table
    if (forward_port_.has_value() && target_chain_.has_value()) {
        return false;  // Cannot use both forwarding and chain targeting
    }
    
    // Validate primary port number range for UDP
    // UDP uses the same port range as TCP (1-65535)
    // Port 0 is reserved for system use and should not be filtered
    if (port_ == 0 || port_ > 65535) {
        return false;  // Invalid primary port range
    }
    
    // Validate forwarding port number range if specified
    // UDP port forwarding uses the same port space constraints as TCP
    if (forward_port_.has_value() && (*forward_port_ == 0 || *forward_port_ > 65535)) {
        return false;  // Invalid forwarding port range
    }
    
    // All validation checks passed
    return true;
}

std::string UdpRule::getValidationError() const {
    // Provide detailed validation error messages for UDP rule troubleshooting
    // This helps users understand and fix configuration issues
    
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

std::string UdpRule::getComment() const {
    // Generate standardized comment for UDP rule identification and management
    // Comment format mirrors TCP rules but specifies UDP protocol
    
    // Extract MAC address for comment, defaulting to "any" if not specified
    // This provides consistent comment formatting across different rule configurations
    std::string mac_comment = mac_source_.value_or("any");
    
    // Generate comment based on rule configuration type
    if (forward_port_) {
        // UDP port forwarding rule: include both source and destination ports
        // UDP forwarding is useful for services like DNS, DHCP, and gaming protocols
        std::string details = "port:" + std::to_string(port_) + ":forward:" + std::to_string(*forward_port_);
        return buildYamlComment(section_name_, "udp", details, mac_comment);
    } else if (target_chain_.has_value()) {
        // Chain targeting rule: include port and target chain information
        // This allows modular UDP rule organization through custom chains
        std::string details = "port:" + std::to_string(port_) + ":chain:" + *target_chain_;
        return buildYamlComment(section_name_, "udp", details, mac_comment);
    } else {
        // Simple UDP port rule: include only the port number
        // This represents basic allow/deny rules for UDP services
        std::string details = "port:" + std::to_string(port_);
        return buildYamlComment(section_name_, "udp", details, mac_comment);
    }
}

std::vector<std::string> UdpRule::buildIptablesCommand() const {
    std::vector<std::string> args;
    
    // Check if this is a UDP port forwarding rule and use specialized command construction
    // UDP port forwarding uses NAT table rules similar to TCP but for UDP protocol
    if (forward_port_) {
        return buildPortForwardingCommand();
    }
    
    // Build standard UDP filter rule for the specified chain and direction
    // This handles normal UDP port filtering in the filter table
    args.push_back("-A");                    // Append rule to chain
    args.push_back(directionToString());     // Specify target chain based on direction
    
    // Specify UDP protocol for packet matching
    // This ensures the rule only matches UDP packets, not TCP or other protocols
    // UDP is connectionless, so state tracking behaves differently than TCP
    args.push_back("-p");
    args.push_back("udp");
    
    // Add interface filtering arguments if specified
    // Interface restrictions limit rule scope to specific network interfaces
    addInterfaceArgs(args);
    
    // Add subnet filtering arguments if specified
    // Source/destination subnet filtering provides network-based access control
    addSubnetArgs(args);
    
    // Add MAC address filtering if specified
    // MAC filtering provides additional layer of access control based on hardware addresses
    // Note: MAC filtering is only effective for local network segments (same broadcast domain)
    if (mac_source_.has_value()) {
        args.push_back("-m");               // Load match module
        args.push_back("mac");              // MAC address matching module
        args.push_back("--mac-source");     // Match source MAC address
        args.push_back(*mac_source_);       // Specific MAC address to match
    }
    
    // Add UDP destination port matching
    // --dport specifies the destination port for incoming UDP packets
    // UDP ports are used differently than TCP (no connection establishment)
    args.push_back("--dport");
    args.push_back(std::to_string(port_));
    
    // Add the target action (ACCEPT, DROP, REJECT) or chain jump
    // This determines what happens to UDP packets matching the rule criteria
    addTargetArgs(args);
    
    // Add identification comment for rule management
    // Comments enable the application to identify and manage its UDP rules
    addCommentArgs(args, getComment());
    
    return args;
}

std::vector<std::string> UdpRule::buildPortForwardingCommand() const {
    std::vector<std::string> args;
    
    // UDP port forwarding uses the NAT table's PREROUTING chain
    // This intercepts UDP packets before routing decisions and redirects them
    // UDP forwarding is commonly used for DNS, DHCP, and gaming services
    args.push_back("-t");           // Specify table
    args.push_back("nat");          // Network Address Translation table
    args.push_back("-A");           // Append rule
    args.push_back("PREROUTING");   // Pre-routing chain for incoming packets
    
    // Specify UDP protocol for the forwarding rule
    // Port forwarding can be protocol-specific (TCP vs UDP have different behaviors)
    args.push_back("-p");
    args.push_back("udp");
    
    // Add input interface filtering if specified
    // Interface filtering for UDP forwarding typically uses input interface only
    // Output interface is not meaningful in PREROUTING chain
    if (interface_.input.has_value()) {
        args.push_back("-i");
        args.push_back(*interface_.input);
    }
    
    // Add subnet filtering for UDP forwarding rules
    // This allows forwarding to be restricted to specific source/destination networks
    addSubnetArgs(args);
    
    // Add MAC address filtering for UDP forwarding if specified
    // MAC filtering can provide additional security for UDP port forwarding
    if (mac_source_.has_value()) {
        args.push_back("-m");
        args.push_back("mac");
        args.push_back("--mac-source");
        args.push_back(*mac_source_);
    }
    
    // Match the original UDP destination port
    // This is the port that incoming UDP packets are trying to reach
    args.push_back("--dport");
    args.push_back(std::to_string(port_));
    
    // Use REDIRECT target to forward to a different UDP port
    // REDIRECT changes the destination port while keeping the same host
    // This works well for local UDP port forwarding scenarios
    args.push_back("-j");
    args.push_back("REDIRECT");
    args.push_back("--to-port");
    args.push_back(std::to_string(*forward_port_));
    
    // Add identification comment for UDP forwarding rule management
    addCommentArgs(args, getComment());
    
    return args;
}

bool UdpRule::matches(const std::string& comment) const {
    // Implement flexible comment matching for UDP rule identification
    // This supports both current and legacy comment formats for rule management
    
    // Primary matching: use current comment format
    // This is the preferred method for newly created UDP rules
    std::string expected_comment = getComment();
    bool primary_match = comment.find(expected_comment) != std::string::npos;
    
    // Fallback matching: support legacy YAML comment format
    // Format: "YAML:section_name:udp:port:port_number"
    // This ensures compatibility with UDP rules created by older versions
    std::string legacy_pattern = "YAML:" + section_name_ + ":udp:port:" + std::to_string(port_);
    bool legacy_match = comment.find(legacy_pattern) != std::string::npos;
    
    // Return true if either matching method succeeds
    // This provides robust UDP rule identification across different comment formats
    return primary_match || legacy_match;
}

} // namespace iptables 