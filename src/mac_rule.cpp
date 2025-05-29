#include "mac_rule.hpp"
#include <stdexcept>
#include <sstream>

namespace iptables {

MacRule::MacRule(const std::string& mac_source,
                 Direction direction,
                 Action action,
                 const InterfaceConfig& interface,
                 const std::vector<std::string>& subnets,
                 const std::string& section_name)
    : Rule(direction, action, interface, subnets)
    , mac_source_(mac_source)
    , section_name_(section_name) {
    
    // MAC rules are only valid for INPUT direction in iptables
    if (direction != Direction::Input) {
        throw std::invalid_argument("MAC rules are only supported for INPUT direction");
    }
    
    // Validate that only input interface is specified for MAC rules
    if (interface_.output.has_value()) {
        throw std::invalid_argument("MAC rules only support input interface specification");
    }
}

std::string MacRule::getComment() const {
    // Enhanced MAC rule comment generation following Rust patterns
    std::string details = "mac:" + mac_source_;
    return buildYamlComment(section_name_, "mac", details, mac_source_);
}

std::vector<std::string> MacRule::buildIptablesCommand() const {
    std::vector<std::string> args;
    
    // MAC rules are always in INPUT chain
    args.push_back("-A");
    args.push_back("INPUT");
    
    // Add input interface if specified (MAC rules only support input interface)
    if (interface_.input.has_value()) {
        args.push_back("-i");
        args.push_back(*interface_.input);
    }
    
    // Add subnet filtering (source filtering for MAC rules)
    addSubnetArgs(args);
    
    // MAC source specification
    args.push_back("-m");
    args.push_back("mac");
    args.push_back("--mac-source");
    args.push_back(mac_source_);
    
    // Action
    args.push_back("-j");
    args.push_back(actionToString());
    
    // Add comment
    addCommentArgs(args, getComment());
    
    return args;
}

bool MacRule::matches(const std::string& comment) const {
    // Enhanced matching to check for YAML comment structure and MAC specifics
    std::string expected_comment = getComment();
    return comment.find(expected_comment) != std::string::npos ||
           (comment.find("YAML:" + section_name_ + ":mac:" + mac_source_) != std::string::npos);
}

} // namespace iptables 