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
                 const std::string& section_name)
    : Rule(direction, action, interface, subnets)
    , port_(port)
    , mac_source_(std::move(mac_source))
    , forward_port_(forward_port)
    , section_name_(section_name) {}

std::string TcpRule::getComment() const {
    std::string mac_comment = mac_source_.value_or("any");
    
    if (forward_port_) {
        std::string details = "port:" + std::to_string(port_) + ":forward:" + std::to_string(*forward_port_);
        return buildYamlComment(section_name_, "tcp", details, mac_comment);
    } else {
        std::string details = "port:" + std::to_string(port_);
        return buildYamlComment(section_name_, "tcp", details, mac_comment);
    }
}

std::vector<std::string> TcpRule::buildIptablesCommand() const {
    std::vector<std::string> args;
    
    // Handle port forwarding (NAT table)
    if (forward_port_) {
        return buildPortForwardingCommand();
    }
    
    // Standard filtering rule (filter table)
    args.push_back("-A");
    args.push_back(directionToString());
    
    // Protocol specification
    args.push_back("-p");
    args.push_back("tcp");
    
    // Add interface arguments
    addInterfaceArgs(args);
    
    // Add subnet filtering
    addSubnetArgs(args);
    
    // Add MAC source filtering if specified
    if (mac_source_.has_value()) {
        args.push_back("-m");
        args.push_back("mac");
        args.push_back("--mac-source");
        args.push_back(*mac_source_);
    }
    
    // Port specification
    args.push_back("--dport");
    args.push_back(std::to_string(port_));
    
    // Action
    args.push_back("-j");
    args.push_back(actionToString());
    
    // Add comment
    addCommentArgs(args, getComment());
    
    return args;
}

std::vector<std::string> TcpRule::buildPortForwardingCommand() const {
    std::vector<std::string> args;
    
    // Port forwarding uses NAT table, PREROUTING chain
    args.push_back("-t");
    args.push_back("nat");
    args.push_back("-A");
    args.push_back("PREROUTING");
    
    // Protocol specification
    args.push_back("-p");
    args.push_back("tcp");
    
    // Only input interface makes sense for PREROUTING
    if (interface_.input.has_value()) {
        args.push_back("-i");
        args.push_back(*interface_.input);
    }
    
    // Add subnet filtering for source
    addSubnetArgs(args);
    
    // Add MAC source filtering if specified
    if (mac_source_.has_value()) {
        args.push_back("-m");
        args.push_back("mac");
        args.push_back("--mac-source");
        args.push_back(*mac_source_);
    }
    
    // Destination port
    args.push_back("--dport");
    args.push_back(std::to_string(port_));
    
    // REDIRECT action with target port
    args.push_back("-j");
    args.push_back("REDIRECT");
    args.push_back("--to-port");
    args.push_back(std::to_string(*forward_port_));
    
    // Add comment
    addCommentArgs(args, getComment());
    
    return args;
}

bool TcpRule::matches(const std::string& comment) const {
    // Enhanced matching to check for YAML comment structure and TCP specifics
    std::string expected_comment = getComment();
    return comment.find(expected_comment) != std::string::npos ||
           (comment.find("YAML:" + section_name_ + ":tcp:port:" + std::to_string(port_)) != std::string::npos);
}

} // namespace iptables 