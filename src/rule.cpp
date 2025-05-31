#include "rule.hpp"
#include <sstream>
#include <algorithm>
#include <cctype>

namespace iptables {

std::string Rule::directionToString() const {
    // Convert Direction enum to iptables command line argument
    // These map directly to iptables chain specification parameters
    switch (direction_) {
        case Direction::Input:
            return "INPUT";
        case Direction::Output:
            return "OUTPUT";
        case Direction::Forward:
            return "FORWARD";
        default:
            throw std::runtime_error("Unknown direction");
    }
}

std::string Rule::actionToString() const {
    // Convert Action enum to iptables target specification
    // These correspond to standard iptables targets and their behavior
    switch (action_) {
        case Action::Accept:
            return "ACCEPT";
        case Action::Drop:
            return "DROP";
        case Action::Reject:
            return "REJECT";
        default:
            throw std::runtime_error("Unknown action");
    }
}

// ✨ NEW: Target resolution (action or chain)
std::string Rule::getTargetString() const {
    if (target_chain_.has_value()) {
        return target_chain_.value();
    }
    return actionToString();
}

// ✨ NEW: Validation for mutual exclusivity and correctness
bool Rule::isValid() const {
    // Comprehensive validation of rule configuration
    // Each check addresses a specific aspect of iptables rule validity
    
    // Validate chain name format and content
    // Chain names must follow iptables naming conventions
    if (target_chain_.has_value() && target_chain_->empty()) {
        return false;  // Chain name is required for all rules
    }
    
    // Check for valid characters in chain name
    // iptables chain names should contain only alphanumeric characters, underscores, and hyphens
    // Maximum length is typically 29 characters in iptables
    if (target_chain_.has_value() && target_chain_->length() > 29) {
        return false;  // Chain name too long for iptables
    }
    
    // Validate chain name characters
    // Only allow alphanumeric, underscore, hyphen, and dot characters
    if (target_chain_.has_value()) {
        const std::string& chain = *target_chain_;
        for (char c : chain) {
            if (!std::isalnum(c) && c != '_' && c != '-' && c != '.') {
                return false;  // Invalid character in chain name
            }
        }
    }
    
    // Chain name cannot start with a hyphen (conflicts with iptables option syntax)
    if (target_chain_.has_value() && target_chain_->front() == '-') {
        return false;  // Chain name cannot start with hyphen
    }
    
    // Additional validation can be performed by derived classes
    // This base implementation provides fundamental checks common to all rule types
    return true;
}

std::string Rule::getValidationError() const {
    if (target_chain_.has_value() && target_chain_->empty()) {
        return "Chain target cannot be empty";
    }
    
    if (target_chain_.has_value()) {
        const std::string& chain = *target_chain_;
        for (char c : chain) {
            if (!std::isalnum(c) && c != '_' && c != '-' && c != '.') {
                return "Chain name '" + chain + "' contains invalid characters. Only alphanumeric, underscore, hyphen, and dot are allowed.";
            }
        }
    }
    
    return "";
}

std::string Rule::getInterfaceComment() const {
    std::string in_iface = interface_.input.value_or("any");
    std::string out_iface = interface_.output.value_or("any");
    return "i:" + in_iface + ":o:" + out_iface;
}

std::string Rule::getSubnetsComment() const {
    if (subnets_.empty()) {
        return "subnets:any";
    }
    
    std::ostringstream oss;
    oss << "subnets:";
    for (size_t i = 0; i < subnets_.size(); ++i) {
        if (i > 0) oss << ",";
        oss << subnets_[i];
    }
    return oss.str();
}

void Rule::addInterfaceArgs(std::vector<std::string>& args) const {
    if (interface_.input.has_value()) {
        args.push_back("-i");
        args.push_back(*interface_.input);
    }
    if (interface_.output.has_value()) {
        args.push_back("-o");
        args.push_back(*interface_.output);
    }
}

void Rule::addSubnetArgs(std::vector<std::string>& args) const {
    if (!subnets_.empty()) {
        // For multiple subnets, we need to handle them properly
        // For now, using the first subnet (iptables doesn't directly support multiple -s flags)
        args.push_back("-s");
        args.push_back(subnets_[0]);
        
        // TODO: For multiple subnets, we might need to create multiple rules
        // or use ipset, but for basic implementation we'll use the first one
    }
}

void Rule::addCommentArgs(std::vector<std::string>& args, const std::string& comment) const {
    args.push_back("-m");
    args.push_back("comment");
    args.push_back("--comment");
    args.push_back(comment);
}

// ✨ NEW: Add target (action or chain)
void Rule::addTargetArgs(std::vector<std::string>& args) const {
    args.push_back("-j");
    args.push_back(getTargetString());
}

std::string Rule::buildYamlComment(const std::string& section_name, 
                                 const std::string& rule_type,
                                 const std::string& details,
                                 const std::string& mac_source) const {
    // Build standardized YAML comment for rule identification
    // Format: YAML:section:type:details:interface:mac
    std::ostringstream comment;
    comment << "YAML:" << section_name 
            << ":" << rule_type 
            << ":" << details
            << ":" << getInterfaceComment()
            << ":mac:" << mac_source;
    return comment.str();
}

} // namespace iptables 