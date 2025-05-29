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
    
    // Helper method to check if any interface is specified
    bool hasInterface() const {
        return input.has_value() || output.has_value();
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

protected:
    Rule(Direction direction, Action action, 
         const InterfaceConfig& interface = InterfaceConfig{},
         const std::vector<std::string>& subnets = {})
        : direction_(direction)
        , action_(action)
        , interface_(interface)
        , subnets_(subnets) {}

    Direction direction_;
    Action action_;
    InterfaceConfig interface_;
    std::vector<std::string> subnets_;

    // Enhanced helper methods for building iptables commands
    std::string directionToString() const;
    std::string actionToString() const;
    std::string getInterfaceComment() const;
    std::string getSubnetsComment() const;
    
    // Helper methods for iptables command construction
    void addInterfaceArgs(std::vector<std::string>& args) const;
    void addSubnetArgs(std::vector<std::string>& args) const;
    void addCommentArgs(std::vector<std::string>& args, const std::string& comment) const;
    
    // Enhanced comment generation following Rust patterns
    std::string buildYamlComment(const std::string& section_name, 
                                const std::string& rule_type,
                                const std::string& details,
                                const std::string& mac_source = "any") const;
};

} // namespace iptables 