#pragma once

#include "rule.hpp"

namespace iptables {

class MacRule : public Rule {
public:
    MacRule(const std::string& mac_source,
            Direction direction,
            Action action,
            const InterfaceConfig& interface = InterfaceConfig{},
            const std::vector<std::string>& subnets = {},
            const std::string& section_name = "default");

    std::string getComment() const override;
    std::vector<std::string> buildIptablesCommand() const override;
    bool matches(const std::string& comment) const override;

    const std::string& getMacSource() const { return mac_source_; }
    const std::string& getSectionName() const { return section_name_; }

private:
    std::string mac_source_;
    std::string section_name_;
};

} // namespace iptables 