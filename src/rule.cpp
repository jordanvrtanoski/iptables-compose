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

std::string Rule::buildYamlComment(const std::string& section_name, 
                                 const std::string& rule_type,
                                 const std::string& details,
                                 const std::string& mac_source) const {
    std::ostringstream comment;
    comment << "YAML:" << section_name << ":" << rule_type << ":" << details;
    comment << ":" << getInterfaceComment();
    comment << ":mac:" << mac_source;
    
    // Add subnet information if present
    if (!subnets_.empty()) {
        comment << ":" << getSubnetsComment();
    }
    
    return comment.str();
}

} // namespace iptables 