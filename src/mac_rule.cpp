#include "mac_rule.hpp"
#include <stdexcept>
#include <sstream>

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
    
    // MAC rules are only valid for INPUT direction in iptables
    if (direction != Direction::Input) {
        throw std::invalid_argument("MAC rules are only supported for INPUT direction");
    }
    
    // Validate that only input interface is specified for MAC rules
    if (interface_.output.has_value()) {
        throw std::invalid_argument("MAC rules only support input interface specification");
    }
}

bool MacRule::isValid() const {
    // Call base class validation first
    if (!Rule::isValid()) {
        return false;
    }
    
    // MAC rules are only allowed in INPUT direction
    if (direction_ != Direction::Input) {
        return false;
    }
    
    // MAC address validation (basic format check)
    if (mac_source_.empty()) {
        return false;
    }
    
    // Basic MAC address format validation (xx:xx:xx:xx:xx:xx)
    if (mac_source_.length() != 17) {
        return false;
    }
    
    for (size_t i = 0; i < mac_source_.length(); ++i) {
        if (i % 3 == 2) {
            if (mac_source_[i] != ':') return false;
        } else {
            if (!std::isxdigit(mac_source_[i])) return false;
        }
    }
    
    return true;
}

std::string MacRule::getValidationError() const {
    // Check base class validation first
    std::string base_error = Rule::getValidationError();
    if (!base_error.empty()) {
        return base_error;
    }
    
    if (direction_ != Direction::Input) {
        return "MAC rules are only allowed in INPUT direction";
    }
    
    if (mac_source_.empty()) {
        return "MAC source cannot be empty";
    }
    
    if (mac_source_.length() != 17) {
        return "MAC address must be in format xx:xx:xx:xx:xx:xx";
    }
    
    for (size_t i = 0; i < mac_source_.length(); ++i) {
        if (i % 3 == 2) {
            if (mac_source_[i] != ':') {
                return "MAC address format invalid: expected ':' at position " + std::to_string(i);
            }
        } else {
            if (!std::isxdigit(mac_source_[i])) {
                return "MAC address format invalid: expected hexadecimal digit at position " + std::to_string(i);
            }
        }
    }
    
    return "";
}

std::string MacRule::getComment() const {
    if (target_chain_.has_value()) {
        // Enhanced MAC rule comment generation following Rust patterns
        std::string details = "mac:" + mac_source_ + ":chain:" + *target_chain_;
        return buildYamlComment(section_name_, "mac", details, mac_source_);
    } else {
        std::string details = "mac:" + mac_source_;
        return buildYamlComment(section_name_, "mac", details, mac_source_);
    }
}

std::vector<std::string> MacRule::buildIptablesCommand() const {
    std::vector<std::string> args;
    
    // MAC rules are only valid in INPUT chain
    args.push_back("-A");
    args.push_back("INPUT");
    
    // Add interface arguments (only input interface makes sense for MAC rules)
    if (interface_.input.has_value()) {
        args.push_back("-i");
        args.push_back(*interface_.input);
    }
    
    // Add subnet filtering
    addSubnetArgs(args);
    
    // MAC source filtering
    args.push_back("-m");
    args.push_back("mac");
    args.push_back("--mac-source");
    args.push_back(mac_source_);
    
    // Use new target method (action or chain)
    addTargetArgs(args);
    
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