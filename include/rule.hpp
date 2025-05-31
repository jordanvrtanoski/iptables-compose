/**
 * @file rule.hpp
 * @brief Base rule class and common enumerations for iptables-compose-cpp
 * @author iptables-compose-cpp Development Team
 * @date 2024
 * 
 * This file contains the abstract Rule base class and common enumerations used
 * throughout the rule system. All specific rule types (TCP, UDP, MAC, Chain)
 * inherit from the base Rule class and implement the pure virtual methods.
 */

#pragma once

#include <string>
#include <memory>
#include <vector>
#include <optional>

namespace iptables {

/**
 * @enum Direction
 * @brief Iptables chain directions for rule application
 * 
 * Represents the iptables chains where rules can be applied:
 * - Input: Rules for incoming traffic (INPUT chain)
 * - Output: Rules for outgoing traffic (OUTPUT chain)  
 * - Forward: Rules for forwarded traffic (FORWARD chain)
 */
enum class Direction {
    Input,   ///< INPUT chain for incoming traffic
    Output,  ///< OUTPUT chain for outgoing traffic
    Forward  ///< FORWARD chain for routed traffic
};

/**
 * @enum Action
 * @brief Iptables target actions for rules
 * 
 * Represents the actions that can be taken when a rule matches:
 * - Accept: Allow the packet (ACCEPT target)
 * - Drop: Silently drop the packet (DROP target)
 * - Reject: Drop packet and send rejection notice (REJECT target)
 */
enum class Action {
    Accept, ///< ACCEPT target - allow packet
    Drop,   ///< DROP target - silently drop packet
    Reject  ///< REJECT target - drop with rejection notice
};

/**
 * @enum Protocol
 * @brief Network protocols supported by rules
 * 
 * Currently supported protocols for port-based rules:
 * - Tcp: Transmission Control Protocol
 * - Udp: User Datagram Protocol
 */
enum class Protocol {
    Tcp, ///< TCP protocol
    Udp  ///< UDP protocol
};

/**
 * @struct InterfaceConfig
 * @brief Network interface configuration for rules
 * 
 * Configures which network interfaces a rule applies to.
 * Supports input interfaces, output interfaces, and chain calls.
 */
struct InterfaceConfig {
    std::optional<std::string> input;  ///< Input interface (-i parameter)
    std::optional<std::string> output; ///< Output interface (-o parameter)
    std::optional<std::string> chain;  ///< Custom chain to call (-j CHAIN)
    
    /**
     * @brief Check if any network interface is specified
     * @return true if input or output interface is configured
     */
    bool hasInterface() const {
        return input.has_value() || output.has_value();
    }
    
    /**
     * @brief Check if this configuration specifies a chain call
     * @return true if a custom chain is specified
     */
    bool hasChain() const {
        return chain.has_value();
    }
};

/**
 * @class Rule
 * @brief Abstract base class for all iptables rules
 * 
 * The Rule class defines the common interface and functionality for all types
 * of iptables rules. It uses the Template Method pattern where derived classes
 * implement specific behavior while the base class provides common operations.
 * 
 * All rules support:
 * - Direction specification (INPUT/OUTPUT/FORWARD chains)
 * - Action or chain target specification
 * - Interface filtering (input/output interfaces)
 * - Subnet filtering (source IP restrictions)
 * - YAML comment generation for rule identification
 */
class Rule {
public:
    /**
     * @brief Virtual destructor for proper cleanup of derived classes
     */
    virtual ~Rule() = default;

    /**
     * @brief Get the YAML comment signature for this rule
     * @return String containing the rule's unique YAML signature
     * 
     * Pure virtual method that must be implemented by derived classes.
     * Returns a unique comment string used to identify the rule in iptables
     * for removal and management operations.
     */
    virtual std::string getComment() const = 0;
    
    /**
     * @brief Build the complete iptables command for this rule
     * @return Vector of command arguments for iptables execution
     * 
     * Pure virtual method that must be implemented by derived classes.
     * Returns the complete iptables command as a vector of arguments
     * ready for execution through CommandExecutor.
     */
    virtual std::vector<std::string> buildIptablesCommand() const = 0;
    
    /**
     * @brief Check if this rule matches a given comment signature
     * @param comment The comment signature to match against
     * @return true if the rule matches the comment signature
     * 
     * Pure virtual method used for rule identification and management.
     * Allows rules to be found and removed based on their comment signatures.
     */
    virtual bool matches(const std::string& comment) const = 0;

    /**
     * @brief Get the direction (chain) for this rule
     * @return Direction enumeration value
     */
    Direction getDirection() const { return direction_; }
    
    /**
     * @brief Get the action for this rule
     * @return Action enumeration value
     */
    Action getAction() const { return action_; }
    
    /**
     * @brief Get the interface configuration for this rule
     * @return Const reference to InterfaceConfig structure
     */
    const InterfaceConfig& getInterface() const { return interface_; }
    
    /**
     * @brief Get the subnet restrictions for this rule
     * @return Const reference to vector of subnet strings
     */
    const std::vector<std::string>& getSubnets() const { return subnets_; }
    
    /**
     * @brief Get the target chain for this rule (if any)
     * @return Optional string containing target chain name
     */
    const std::optional<std::string>& getTargetChain() const { return target_chain_; }
    
    /**
     * @brief Check if this rule has a chain target instead of an action
     * @return true if a target chain is specified
     */
    bool hasChainTarget() const { return target_chain_.has_value(); }
    
    /**
     * @brief Validate that the rule configuration is valid
     * @return true if the rule is valid, false otherwise
     * 
     * Validates mutual exclusivity constraints and configuration consistency.
     * For example, a rule cannot have both an action and a chain target.
     */
    bool isValid() const;
    
    /**
     * @brief Get detailed validation error message if rule is invalid
     * @return String containing validation error details
     */
    std::string getValidationError() const;

protected:
    /**
     * @brief Protected constructor for derived classes
     * @param direction The iptables chain direction
     * @param action The rule action (Accept, Drop, Reject)
     * @param interface Network interface configuration
     * @param subnets Vector of subnet restrictions
     * @param target_chain Optional target chain for jump operations
     */
    Rule(Direction direction, Action action, 
         const InterfaceConfig& interface = InterfaceConfig{},
         const std::vector<std::string>& subnets = {},
         const std::optional<std::string>& target_chain = std::nullopt)
        : direction_(direction)
        , action_(action)
        , interface_(interface)
        , subnets_(subnets)
        , target_chain_(target_chain) {}

    Direction direction_;                              ///< Rule direction (chain)
    Action action_;                                    ///< Rule action
    InterfaceConfig interface_;                        ///< Interface configuration
    std::vector<std::string> subnets_;                ///< Subnet restrictions
    std::optional<std::string> target_chain_;         ///< Target chain for jumps

    /**
     * @brief Convert direction enum to string representation
     * @return String representation of the direction
     */
    std::string directionToString() const;
    
    /**
     * @brief Convert action enum to string representation
     * @return String representation of the action
     */
    std::string actionToString() const;
    
    /**
     * @brief Generate interface comment part for YAML signatures
     * @return String containing interface information for comments
     */
    std::string getInterfaceComment() const;
    
    /**
     * @brief Generate subnet comment part for YAML signatures
     * @return String containing subnet information for comments
     */
    std::string getSubnetsComment() const;
    
    /**
     * @brief Get the target string (action or chain) for iptables commands
     * @return String containing the appropriate target (-j parameter)
     */
    std::string getTargetString() const;
    
    /**
     * @brief Add interface arguments to iptables command
     * @param args Reference to argument vector to modify
     */
    void addInterfaceArgs(std::vector<std::string>& args) const;
    
    /**
     * @brief Add subnet arguments to iptables command
     * @param args Reference to argument vector to modify
     */
    void addSubnetArgs(std::vector<std::string>& args) const;
    
    /**
     * @brief Add comment arguments to iptables command
     * @param args Reference to argument vector to modify
     * @param comment The comment string to add
     */
    void addCommentArgs(std::vector<std::string>& args, const std::string& comment) const;
    
    /**
     * @brief Add target arguments (action or chain) to iptables command
     * @param args Reference to argument vector to modify
     */
    void addTargetArgs(std::vector<std::string>& args) const;
    
    /**
     * @brief Build YAML comment following standard patterns
     * @param section_name Name of the configuration section
     * @param rule_type Type of rule (port, mac, chain)
     * @param details Rule-specific details
     * @param mac_source MAC source information (default: "any")
     * @return String containing the complete YAML comment
     * 
     * Generates standardized YAML comments that match the Rust implementation
     * format: "YAML:section:type:details:interface:mac"
     */
    std::string buildYamlComment(const std::string& section_name, 
                                const std::string& rule_type,
                                const std::string& details,
                                const std::string& mac_source = "any") const;
};

} // namespace iptables 