#include "rule_manager.hpp"
#include <algorithm>
#include <iostream>
#include <sstream>
#include <regex>

namespace iptables {

void RuleManager::addRule(std::shared_ptr<Rule> rule) {
    rules_.push_back(rule);
}

void RuleManager::removeRule(const std::string& comment) {
    rules_.erase(
        std::remove_if(rules_.begin(), rules_.end(),
            [&comment](const std::shared_ptr<Rule>& rule) {
                return rule->matches(comment);
            }),
        rules_.end()
    );
}

void RuleManager::clearRules() {
    rules_.clear();
}

bool RuleManager::applyRules() {
    bool success = true;
    
    for (const auto& rule : rules_) {
        auto commands = rule->buildIptablesCommand();
        if (!commands.empty()) {
            auto result = CommandExecutor::executeIptables(commands);
            if (!result.isSuccess()) {
                std::cerr << "Failed to apply rule: " << rule->getComment() << std::endl;
                std::cerr << "Error: " << result.getErrorMessage() << std::endl;
                success = false;
            }
        }
    }
    
    return success;
}

bool RuleManager::removeAllRules() {
    // Flush all chains in filter table
    auto result = CommandExecutor::flushChain("filter", "");
    if (!result.isSuccess()) {
        std::cerr << "Failed to flush filter table: " << result.getErrorMessage() << std::endl;
        return false;
    }
    
    // Clear our internal rule collection
    clearRules();
    return true;
}

bool RuleManager::setPolicy(Direction direction, Action action) {
    std::string chain = getChainName(direction);
    std::string policy = actionToString(action);
    
    auto result = CommandExecutor::setChainPolicy("filter", chain, policy);
    if (!result.isSuccess()) {
        std::cerr << "Failed to set policy for " << chain << " to " << policy 
                  << ": " << result.getErrorMessage() << std::endl;
        return false;
    }
    
    return true;
}

bool RuleManager::resetPolicies() {
    bool success = true;
    
    // Reset all main chain policies to ACCEPT
    std::vector<std::string> chains = {"INPUT", "OUTPUT", "FORWARD"};
    for (const auto& chain : chains) {
        auto result = CommandExecutor::setChainPolicy("filter", chain, "ACCEPT");
        if (!result.isSuccess()) {
            std::cerr << "Failed to reset policy for " << chain 
                      << ": " << result.getErrorMessage() << std::endl;
            success = false;
        }
    }
    
    return success;
}

std::vector<std::shared_ptr<Rule>> RuleManager::getRulesByComment(const std::string& comment) const {
    std::vector<std::shared_ptr<Rule>> matching_rules;
    
    for (const auto& rule : rules_) {
        if (rule->matches(comment)) {
            matching_rules.push_back(rule);
        }
    }
    
    return matching_rules;
}

std::vector<std::shared_ptr<Rule>> RuleManager::getRulesByDirection(Direction direction) const {
    std::vector<std::shared_ptr<Rule>> matching_rules;
    
    for (const auto& rule : rules_) {
        if (rule->getDirection() == direction) {
            matching_rules.push_back(rule);
        }
    }
    
    return matching_rules;
}

std::vector<std::shared_ptr<Rule>> RuleManager::getAllRules() const {
    return rules_;
}

bool RuleManager::removeRulesBySignature(const std::string& chain, 
                                        const std::string& comment,
                                        const std::string& table) {
    auto line_numbers = getRuleLineNumbers(chain, comment, table);
    
    if (line_numbers.empty()) {
        return true; // No rules to remove
    }
    
    // Sort line numbers in descending order to avoid shifting
    std::sort(line_numbers.rbegin(), line_numbers.rend());
    
    bool success = true;
    for (uint32_t line_num : line_numbers) {
        auto result = CommandExecutor::removeRuleByLineNumber(table, chain, line_num);
        if (!result.isSuccess()) {
            std::cerr << "Failed to remove rule at line " << line_num 
                      << " from " << table << ":" << chain 
                      << ": " << result.getErrorMessage() << std::endl;
            success = false;
        }
    }
    
    return success;
}

bool RuleManager::removeAllYamlRules() {
    bool success = true;
    
    // Define chains and tables to check
    std::vector<std::string> tables = {"filter", "nat", "mangle"};
    std::vector<std::string> chains = {"INPUT", "OUTPUT", "FORWARD", "PREROUTING", "POSTROUTING"};
    
    for (const auto& table : tables) {
        for (const auto& chain : chains) {
            // Remove all rules with YAML comments
            if (!removeRulesBySignature(chain, "YAML:", table)) {
                success = false;
            }
        }
    }
    
    return success;
}

bool RuleManager::resetAllPolicies() {
    bool success = true;
    
    // Reset policies for all main chains in filter table
    std::vector<std::string> chains = {"INPUT", "OUTPUT", "FORWARD"};
    for (const auto& chain : chains) {
        auto result = CommandExecutor::setChainPolicy("filter", chain, "ACCEPT");
        if (!result.isSuccess()) {
            std::cerr << "Failed to reset policy for " << chain 
                      << ": " << result.getErrorMessage() << std::endl;
            success = false;
        }
    }
    
    return success;
}

bool RuleManager::executeIptablesCommand(const std::vector<std::string>& args) const {
    auto result = CommandExecutor::executeIptables(args);
    if (!result.isSuccess()) {
        std::cerr << "iptables command failed: " << result.getErrorMessage() << std::endl;
        return false;
    }
    return true;
}

std::vector<uint32_t> RuleManager::getRuleLineNumbers(const std::string& chain, 
                                                     const std::string& comment,
                                                     const std::string& table) const {
    std::vector<uint32_t> line_numbers;
    
    // List rules with line numbers for the specified chain
    auto result = CommandExecutor::listRules(table, chain);
    if (!result.isSuccess()) {
        return line_numbers; // Return empty vector on failure
    }
    
    // Parse the output to find rules with matching comments
    std::istringstream stream(result.stdout_output);
    std::string line;
    std::regex line_regex(R"(^\s*(\d+)\s+.*)" + comment + R"(.*)");
    std::smatch match;
    
    while (std::getline(stream, line)) {
        if (std::regex_search(line, match, line_regex)) {
            try {
                uint32_t line_num = std::stoul(match[1].str());
                line_numbers.push_back(line_num);
            } catch (const std::exception& e) {
                std::cerr << "Failed to parse line number from: " << line << std::endl;
            }
        }
    }
    
    return line_numbers;
}

std::string RuleManager::getChainName(Direction direction) const {
    return directionToString(direction);
}

std::string RuleManager::directionToString(Direction direction) const {
    switch (direction) {
        case Direction::Input:
            return "INPUT";
        case Direction::Output:
            return "OUTPUT";
        case Direction::Forward:
            return "FORWARD";
        default:
            return "INPUT";
    }
}

std::string RuleManager::actionToString(Action action) const {
    switch (action) {
        case Action::Accept:
            return "ACCEPT";
        case Action::Drop:
            return "DROP";
        case Action::Reject:
            return "REJECT";
        default:
            return "ACCEPT";
    }
}

} // namespace iptables 