#include "chain_rule.hpp"
#include <sstream>

namespace iptables {

ChainRule::ChainRule(const std::string& target_chain,
                     Direction direction,
                     const InterfaceConfig& interface,
                     const std::vector<std::string>& subnets,
                     const std::string& section_name)
    : Rule(direction, Action::Accept, interface, subnets)  // Use Accept as placeholder since we jump to chain
    , target_chain_(target_chain)
    , section_name_(section_name) {}

std::string ChainRule::getComment() const {
    std::string details = "chain_call:" + target_chain_;
    return buildYamlComment(section_name_, "chain_call", details, "any");
}

std::vector<std::string> ChainRule::buildIptablesCommand() const {
    std::vector<std::string> args;
    
    // Standard chain call rule (filter table)
    args.push_back("-A");
    args.push_back(directionToString());
    
    // Add interface arguments
    addInterfaceArgs(args);
    
    // Add subnet filtering
    addSubnetArgs(args);
    
    // Jump to target chain
    args.push_back("-j");
    args.push_back(target_chain_);
    
    // Add comment
    addCommentArgs(args, getComment());
    
    return args;
}

bool ChainRule::matches(const std::string& comment) const {
    // Enhanced matching to check for YAML comment structure and chain call specifics
    std::string expected_comment = getComment();
    return comment.find(expected_comment) != std::string::npos ||
           (comment.find("YAML:" + section_name_ + ":chain_call:" + target_chain_) != std::string::npos);
}

} // namespace iptables 