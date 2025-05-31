#pragma once

#include "rule.hpp"

namespace iptables {

class ChainRule : public Rule {
public:
    ChainRule(const std::string& target_chain,
              Direction direction,
              const InterfaceConfig& interface = InterfaceConfig{},
              const std::vector<std::string>& subnets = {},
              const std::string& section_name = "default");

    std::string getComment() const override;
    std::vector<std::string> buildIptablesCommand() const override;
    bool matches(const std::string& comment) const override;

    const std::string& getTargetChain() const { return target_chain_; }
    const std::string& getSectionName() const { return section_name_; }

private:
    std::string target_chain_;
    std::string section_name_;
};

} // namespace iptables 