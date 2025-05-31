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
    , section_name_(section_name) {}

bool TcpRule::isValid() const {
    if (!Rule::isValid()) {
        return false;
    }
    
    if (forward_port_.has_value() && target_chain_.has_value()) {
        return false;
    }
    
    if (port_ == 0 || port_ > 65535) {
        return false;
    }
    
    if (forward_port_.has_value() && (*forward_port_ == 0 || *forward_port_ > 65535)) {
        return false;
    }
    
    return true;
}

std::string TcpRule::getValidationError() const {
    std::string base_error = Rule::getValidationError();
    if (!base_error.empty()) {
        return base_error;
    }
    
    if (forward_port_.has_value() && target_chain_.has_value()) {
        return "Port forwarding cannot be used with chain targets";
    }
    
    if (port_ == 0 || port_ > 65535) {
        return "Port number must be between 1 and 65535";
    }
    
    if (forward_port_.has_value() && (*forward_port_ == 0 || *forward_port_ > 65535)) {
        return "Forward port number must be between 1 and 65535";
    }
    
    return "";
}

std::string TcpRule::getComment() const {
    std::string mac_comment = mac_source_.value_or("any");
    
    if (forward_port_) {
        std::string details = "port:" + std::to_string(port_) + ":forward:" + std::to_string(*forward_port_);
        return buildYamlComment(section_name_, "tcp", details, mac_comment);
    } else if (target_chain_.has_value()) {
        std::string details = "port:" + std::to_string(port_) + ":chain:" + *target_chain_;
        return buildYamlComment(section_name_, "tcp", details, mac_comment);
    } else {
        std::string details = "port:" + std::to_string(port_);
        return buildYamlComment(section_name_, "tcp", details, mac_comment);
    }
}

std::vector<std::string> TcpRule::buildIptablesCommand() const {
    std::vector<std::string> args;
    
    if (forward_port_) {
        return buildPortForwardingCommand();
    }
    
    args.push_back("-A");
    args.push_back(directionToString());
    
    args.push_back("-p");
    args.push_back("tcp");
    
    addInterfaceArgs(args);
    
    addSubnetArgs(args);
    
    if (mac_source_.has_value()) {
        args.push_back("-m");
        args.push_back("mac");
        args.push_back("--mac-source");
        args.push_back(*mac_source_);
    }
    
    args.push_back("--dport");
    args.push_back(std::to_string(port_));
    
    addTargetArgs(args);
    
    addCommentArgs(args, getComment());
    
    return args;
}

std::vector<std::string> TcpRule::buildPortForwardingCommand() const {
    std::vector<std::string> args;
    
    args.push_back("-t");
    args.push_back("nat");
    args.push_back("-A");
    args.push_back("PREROUTING");
    
    args.push_back("-p");
    args.push_back("tcp");
    
    if (interface_.input.has_value()) {
        args.push_back("-i");
        args.push_back(*interface_.input);
    }
    
    addSubnetArgs(args);
    
    if (mac_source_.has_value()) {
        args.push_back("-m");
        args.push_back("mac");
        args.push_back("--mac-source");
        args.push_back(*mac_source_);
    }
    
    args.push_back("--dport");
    args.push_back(std::to_string(port_));
    
    args.push_back("-j");
    args.push_back("REDIRECT");
    args.push_back("--to-port");
    args.push_back(std::to_string(*forward_port_));
    
    addCommentArgs(args, getComment());
    
    return args;
}

bool TcpRule::matches(const std::string& comment) const {
    std::string expected_comment = getComment();
    return comment.find(expected_comment) != std::string::npos ||
           (comment.find("YAML:" + section_name_ + ":tcp:port:" + std::to_string(port_)) != std::string::npos);
}

} // namespace iptables 