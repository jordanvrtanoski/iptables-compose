/**
 * @file tcp_rule.hpp
 * @brief TCP protocol rule implementation for iptables-compose-cpp
 * @author iptables-compose-cpp Development Team
 * @date 2024
 * 
 * This file contains the TcpRule class which implements TCP-specific iptables
 * rules with support for port filtering, port forwarding, MAC source filtering,
 * and multiport functionality.
 */

#pragma once

#include "rule.hpp"

namespace iptables {

/**
 * @class TcpRule
 * @brief TCP protocol rule implementation
 * 
 * The TcpRule class implements iptables rules for TCP traffic. It supports:
 * - Single port filtering with --dport
 * - Port forwarding using NAT table PREROUTING chain
 * - MAC source address filtering
 * - Interface-based filtering (input/output)
 * - Subnet-based source filtering
 * - Chain target calls for custom chains
 * 
 * TCP rules generate iptables commands with the -p tcp parameter and use
 * the tcp module for port matching. Port forwarding rules use the NAT
 * table with REDIRECT target.
 */
class TcpRule : public Rule {
public:
    /**
     * @brief Construct a TCP rule with specified parameters
     * @param port The TCP port number to match (1-65535)
     * @param direction The iptables chain direction (INPUT/OUTPUT/FORWARD)
     * @param action The action to take (ACCEPT/DROP/REJECT)
     * @param interface Network interface configuration
     * @param subnets Vector of source subnet restrictions
     * @param mac_source Optional MAC source address for filtering
     * @param forward_port Optional destination port for port forwarding
     * @param section_name Configuration section name for YAML comments
     * @param target_chain Optional custom chain to call instead of action
     * 
     * Creates a TCP rule with the specified parameters. The rule will match
     * TCP traffic on the specified port and apply the configured action or
     * jump to the specified chain. Port forwarding is supported only for
     * INPUT direction rules.
     */
    TcpRule(uint16_t port, 
            Direction direction,
            Action action,
            const InterfaceConfig& interface = InterfaceConfig{},
            const std::vector<std::string>& subnets = {},
            std::optional<std::string> mac_source = std::nullopt,
            std::optional<uint16_t> forward_port = std::nullopt,
            const std::string& section_name = "default",
            const std::optional<std::string>& target_chain = std::nullopt);

    /**
     * @brief Get the YAML comment signature for this TCP rule
     * @return String containing the rule's unique YAML signature
     * 
     * Generates a standardized comment following the pattern:
     * "YAML:section:port:PORT:i:interface:o:interface:mac:source"
     * This comment is used for rule identification and management.
     */
    std::string getComment() const override;
    
    /**
     * @brief Build the complete iptables command for this TCP rule
     * @return Vector of command arguments for iptables execution
     * 
     * Generates the complete iptables command including:
     * - Protocol specification (-p tcp)
     * - Port matching (--dport or -m tcp --dport)
     * - Interface specifications (-i/-o)
     * - Subnet filtering (-s)
     * - MAC source filtering (-m mac --mac-source)
     * - Target action or chain (-j)
     * - Rule comment (-m comment --comment)
     * 
     * For port forwarding rules, generates NAT table commands instead.
     */
    std::vector<std::string> buildIptablesCommand() const override;
    
    /**
     * @brief Check if this rule matches a given comment signature
     * @param comment The comment signature to match against
     * @return true if the rule matches the comment signature
     * 
     * Compares the provided comment string with this rule's generated
     * comment to determine if they represent the same rule configuration.
     */
    bool matches(const std::string& comment) const override;

    /**
     * @brief Get the TCP port number for this rule
     * @return The port number (1-65535)
     */
    uint16_t getPort() const { return port_; }
    
    /**
     * @brief Get the port forwarding destination port (if any)
     * @return Optional port number for forwarding destination
     */
    std::optional<uint16_t> getForwardPort() const { return forward_port_; }
    
    /**
     * @brief Get the MAC source address filter (if any)
     * @return Optional MAC address string for source filtering
     */
    std::optional<std::string> getMacSource() const { return mac_source_; }
    
    /**
     * @brief Get the configuration section name
     * @return String containing the YAML section name
     */
    const std::string& getSectionName() const { return section_name_; }

    /**
     * @brief Validate that the TCP rule configuration is valid
     * @return true if the rule is valid, false otherwise
     * 
     * Validates the rule configuration including:
     * - Port number is in valid range (1-65535)
     * - Port forwarding constraints (only with INPUT direction)
     * - MAC source format validation
     * - Chain target vs action mutual exclusivity
     */
    bool isValid() const;
    
    /**
     * @brief Get detailed validation error message if rule is invalid
     * @return String containing validation error details
     */
    std::string getValidationError() const;

private:
    uint16_t port_;                            ///< TCP port number to match
    std::optional<std::string> mac_source_;    ///< MAC source address filter
    std::optional<uint16_t> forward_port_;     ///< Port forwarding destination
    std::string section_name_;                 ///< Configuration section name
    
    /**
     * @brief Build iptables command for port forwarding
     * @return Vector of command arguments for NAT table rule
     * 
     * Generates a specialized iptables command for port forwarding using
     * the NAT table PREROUTING chain with REDIRECT target. Only used
     * when forward_port_ is specified.
     */
    std::vector<std::string> buildPortForwardingCommand() const;
};

} // namespace iptables 