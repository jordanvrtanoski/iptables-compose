#pragma once

#include "rule.hpp"

namespace iptables {

class TcpRule : public Rule {
public:
    TcpRule(uint16_t port, 
            Direction direction,
            Action action,
            const InterfaceConfig& interface = InterfaceConfig{},
            const std::vector<std::string>& subnets = {},
            std::optional<std::string> mac_source = std::nullopt,
            std::optional<uint16_t> forward_port = std::nullopt,
            const std::string& section_name = "default");

    std::string getComment() const override;
    std::vector<std::string> buildIptablesCommand() const override;
    bool matches(const std::string& comment) const override;

    uint16_t getPort() const { return port_; }
    std::optional<uint16_t> getForwardPort() const { return forward_port_; }
    std::optional<std::string> getMacSource() const { return mac_source_; }
    const std::string& getSectionName() const { return section_name_; }

private:
    uint16_t port_;
    std::optional<std::string> mac_source_;
    std::optional<uint16_t> forward_port_;
    std::string section_name_;
    
    // Helper method for port forwarding rules
    std::vector<std::string> buildPortForwardingCommand() const;
};

} // namespace iptables 