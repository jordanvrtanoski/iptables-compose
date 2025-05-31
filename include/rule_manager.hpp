#pragma once

#include "rule.hpp"
#include "tcp_rule.hpp"
#include "udp_rule.hpp"
#include "mac_rule.hpp"
#include "chain_rule.hpp"
#include "command_executor.hpp"
#include <memory>
#include <vector>
#include <string>
#include <unordered_map>

namespace iptables {

class RuleManager {
public:
    RuleManager() = default;
    ~RuleManager() = default;

    // Rule management
    void addRule(std::shared_ptr<Rule> rule);
    void removeRule(const std::string& comment);
    void clearRules();

    // Rule application
    bool applyRules();
    bool removeAllRules();

    // Policy management
    bool setPolicy(Direction direction, Action action);
    bool resetPolicies();

    // Rule querying
    std::vector<std::shared_ptr<Rule>> getRulesByComment(const std::string& comment) const;
    std::vector<std::shared_ptr<Rule>> getRulesByDirection(Direction direction) const;
    std::vector<std::shared_ptr<Rule>> getAllRules() const;

    // Enhanced rule management for YAML compatibility
    bool removeRulesBySignature(const std::string& chain, 
                               const std::string& comment,
                               const std::string& table = "filter");
    bool removeAllYamlRules();
    bool resetAllPolicies();

private:
    std::vector<std::shared_ptr<Rule>> rules_;
    
    // Helper methods
    bool executeIptablesCommand(const std::vector<std::string>& args) const;
    std::vector<uint32_t> getRuleLineNumbers(const std::string& chain, 
                                           const std::string& comment,
                                           const std::string& table = "filter") const;
    std::string getChainName(Direction direction) const;
    std::string directionToString(Direction direction) const;
    std::string actionToString(Action action) const;
};

} // namespace iptables 