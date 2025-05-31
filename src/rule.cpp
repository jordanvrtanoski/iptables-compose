#include "rule.hpp"
#include <sstream>

namespace iptables {

std::string Rule::directionToString() const {
    switch (direction_) {
        case Direction::Input:
            return "INPUT";
        case Direction::Output:
            return "OUTPUT";
        case Direction::Forward:
            return "FORWARD";
        default:
            return "UNKNOWN";
    }
}

std::string Rule::actionToString() const {
    switch (action_) {
        case Action::Accept:
            return "ACCEPT";
        case Action::Drop:
            return "DROP";
        case Action::Reject:
            return "REJECT";
        default:
            return "UNKNOWN";
    }
}

// ✨ NEW: Target resolution (action or chain)
std::string Rule::getTargetString() const {
    if (target_chain_.has_value()) {
        return *target_chain_;
    }
    return actionToString();
}

// ✨ NEW: Validation for mutual exclusivity and correctness
bool Rule::isValid() const {
    // Note: For now we allow both action and chain to be set
    // The target_chain takes precedence if set
    // This allows backward compatibility while enabling chain support
    
    // Chain name validation (if set)
    if (target_chain_.has_value()) {
        const std::string& chain = *target_chain_;
        // Basic chain name validation: non-empty, alphanumeric with underscores
        if (chain.empty()) {
            return false;
        }
        for (char c : chain) {
            if (!std::isalnum(c) && c != '_' && c != '-') {
                return false;
            }
        }
    }
    
    return true;
}

std::string Rule::getValidationError() const {
    if (target_chain_.has_value() && target_chain_->empty()) {
        return "Chain target cannot be empty";
    }
    
    if (target_chain_.has_value()) {
        const std::string& chain = *target_chain_;
        for (char c : chain) {
            if (!std::isalnum(c) && c != '_' && c != '-') {
                return "Chain name '" + chain + "' contains invalid characters. Only alphanumeric, underscore, and hyphen are allowed.";
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
    std::ostringstream comment;
    comment << "YAML:" << section_name << ":" << rule_type << ":" << details;
    comment << ":" << getInterfaceComment();
    comment << ":mac:" << mac_source;
    
    // Add target information if it's a chain
    if (target_chain_.has_value()) {
        comment << ":target:" << *target_chain_;
    }
    
    // Add subnet information if present
    if (!subnets_.empty()) {
        comment << ":" << getSubnetsComment();
    }
    
    return comment.str();
}

} // namespace iptables 