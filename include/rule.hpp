#pragma once

#include <string>
#include <memory>
#include <vector>
#include <optional>

namespace iptables {

enum class Direction {
    Input,
    Output,
    Forward
};

enum class Action {
    Accept,
    Drop,
    Reject
};

enum class Protocol {
    Tcp,
    Udp
};

struct InterfaceConfig {
    std::optional<std::string> input;
    std::optional<std::string> output;
    std::optional<std::string> chain;
    
    // Helper method to check if any interface is specified
    bool hasInterface() const {
        return input.has_value() || output.has_value();
    }
    
    // Helper method to check if this config specifies a chain call
    bool hasChain() const {
        return chain.has_value();
    }
};

class Rule {
public:
    virtual ~Rule() = default;

    // Pure virtual methods that must be implemented by derived classes
    virtual std::string getComment() const = 0;
    virtual std::vector<std::string> buildIptablesCommand() const = 0;
    virtual bool matches(const std::string& comment) const = 0;

    // Common getters
    Direction getDirection() const { return direction_; }
    Action getAction() const { return action_; }
    const InterfaceConfig& getInterface() const { return interface_; }
    const std::vector<std::string>& getSubnets() const { return subnets_; }
    
    // ✨ NEW: Chain target support
    const std::optional<std::string>& getTargetChain() const { return target_chain_; }
    bool hasChainTarget() const { return target_chain_.has_value(); }
    
    // Validation for mutual exclusivity between action and chain
    bool isValid() const;
    std::string getValidationError() const;

protected:
    Rule(Direction direction, Action action, 
         const InterfaceConfig& interface = InterfaceConfig{},
         const std::vector<std::string>& subnets = {},
         const std::optional<std::string>& target_chain = std::nullopt)
        : direction_(direction)
        , action_(action)
        , interface_(interface)
        , subnets_(subnets)
        , target_chain_(target_chain) {}

    Direction direction_;
    Action action_;
    InterfaceConfig interface_;
    std::vector<std::string> subnets_;
    std::optional<std::string> target_chain_;  // ✨ NEW: Target chain for jump commands

    // Enhanced helper methods for building iptables commands
    std::string directionToString() const;
    std::string actionToString() const;
    std::string getInterfaceComment() const;
    std::string getSubnetsComment() const;
    
    // ✨ NEW: Target resolution (action or chain)
    std::string getTargetString() const;
    
    // Helper methods for iptables command construction
    void addInterfaceArgs(std::vector<std::string>& args) const;
    void addSubnetArgs(std::vector<std::string>& args) const;
    void addCommentArgs(std::vector<std::string>& args, const std::string& comment) const;
    void addTargetArgs(std::vector<std::string>& args) const;  // ✨ NEW: Add target (action or chain)
    
    // Enhanced comment generation following Rust patterns
    std::string buildYamlComment(const std::string& section_name, 
                                const std::string& rule_type,
                                const std::string& details,
                                const std::string& mac_source = "any") const;
};

} // namespace iptables 