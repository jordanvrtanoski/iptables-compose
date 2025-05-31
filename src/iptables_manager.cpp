#include "iptables_manager.hpp"
#include "config_parser.hpp"
#include "system_utils.hpp"
#include "command_executor.hpp"
#include "rule_validator.hpp"
#include <iostream>
#include <sstream>
#include <algorithm>

namespace iptables {

// Helper function to convert Policy enum to string
std::string policyToString(Policy policy) {
    switch (policy) {
        case Policy::Accept: return "ACCEPT";
        case Policy::Drop: return "DROP";
        case Policy::Reject: return "REJECT";
        default: return "ACCEPT";
    }
}

std::string actionToString(Action action) {
    switch (action) {
        case Action::Accept: return "ACCEPT";
        case Action::Drop: return "DROP";
        case Action::Reject: return "REJECT";
        default: return "ACCEPT";
    }
}

// Helper function to generate interface comment
std::string getInterfaceComment(const std::optional<InterfaceConfig>& interface) {
    if (interface.has_value()) {
        std::string in_iface = interface->input.value_or("any");
        std::string out_iface = interface->output.value_or("any");
        return "i:" + in_iface + ":o:" + out_iface;
    }
    return "i:any:o:any";
}

// Helper function to get rule line numbers by comment signature
std::vector<uint32_t> getRuleLineNumbers(const std::string& table, const std::string& chain, const std::string& comment) {
    std::vector<uint32_t> line_numbers;
    
    // Execute iptables -L with line numbers
    std::vector<std::string> cmd_args = {"-t", table, "-L", chain, "--line-numbers"};
    auto result = CommandExecutor::executeIptables(cmd_args);
    
    if (!result.isSuccess()) {
        // Chain might not exist, return empty list
        return line_numbers;
    }
    
    // Parse output to find matching rules
    std::istringstream iss(result.stdout_output);
    std::string line;
    while (std::getline(iss, line)) {
        if (line.find(comment) != std::string::npos) {
            // Extract line number (first token)
            std::istringstream line_stream(line);
            std::string line_num_str;
            if (line_stream >> line_num_str) {
                try {
                    uint32_t line_num = std::stoul(line_num_str);
                    line_numbers.push_back(line_num);
                } catch (const std::exception&) {
                    // Not a number, skip
                }
            }
        }
    }
    
    return line_numbers;
}

// Helper function to remove rules by signature
bool removeRulesBySignature(const std::string& table, const std::string& chain, const std::string& comment) {
    auto line_numbers = getRuleLineNumbers(table, chain, comment);
    
    // Sort in descending order to delete from bottom to top
    std::sort(line_numbers.begin(), line_numbers.end(), std::greater<uint32_t>());
    
    bool success = true;
    for (uint32_t line_num : line_numbers) {
        auto result = CommandExecutor::removeRuleByLineNumber(table, chain, line_num);
        if (!result.isSuccess()) {
            std::cerr << "Failed to remove rule at line " << line_num << ": " << result.getErrorMessage() << std::endl;
            success = false;
        }
    }
    
    return success;
}

bool IptablesManager::loadConfig(const std::filesystem::path& config_path) {
    try {
        std::cout << "Loading configuration from: " << config_path << std::endl;
        
        // Use ConfigParser to load the configuration
        Config config = ConfigParser::loadFromFile(config_path.string());
        
        std::cout << "Configuration loaded successfully" << std::endl;
        
        // Validate rule order before applying configuration
        std::cout << "Validating rule order..." << std::endl;
        auto warnings = RuleValidator::validateRuleOrder(config);
        
        if (!warnings.empty()) {
            std::cout << "Found " << warnings.size() << " potential rule ordering issue(s):" << std::endl;
            for (const auto& warning : warnings) {
                switch (warning.type) {
                    case ValidationWarning::Type::UnreachableRule:
                        std::cout << "  WARNING (Unreachable Rule): " << warning.message << std::endl;
                        break;
                    case ValidationWarning::Type::RedundantRule:
                        std::cout << "  WARNING (Redundant Rule): " << warning.message << std::endl;
                        break;
                    case ValidationWarning::Type::SubnetOverlap:
                        std::cout << "  WARNING (Subnet Overlap): " << warning.message << std::endl;
                        break;
                }
            }
            std::cout << "These warnings indicate potential misconfigurations where rules may not work as expected." << std::endl;
            std::cout << "Consider reordering rules to place more specific conditions before general ones." << std::endl;
            std::cout << std::endl;
        } else {
            std::cout << "Rule order validation passed - no issues detected." << std::endl;
        }
        
        // Process filter section if present
        if (config.filter) {
            std::cout << "Processing filter section" << std::endl;
            if (!processFilterConfig(*config.filter)) {
                std::cerr << "Failed to process filter configuration" << std::endl;
                return false;
            }
        }
        
        // Process custom sections in the order they appear in YAML
        std::cout << "Custom sections: " << config.custom_sections.size() << std::endl;
        for (const auto& [section_name, section] : config.custom_sections) {
            std::cout << "Processing section: " << section_name << std::endl;
            
            // Process port rules in order
            if (section.ports) {
                for (const auto& port : *section.ports) {
                    if (!processPortConfig(port, section_name)) {
                        std::cerr << "Failed to process port configuration in section " << section_name << std::endl;
                        return false;
                    }
                }
            }
            
            // Process MAC rules in order
            if (section.mac) {
                for (const auto& mac : *section.mac) {
                    if (!processMacConfig(mac, section_name)) {
                        std::cerr << "Failed to process MAC configuration in section " << section_name << std::endl;
                        return false;
                    }
                }
            }
            
            // Process interface rules in order
            if (section.interface) {
                for (const auto& interface : *section.interface) {
                    if (!processInterfaceConfig(interface, section_name)) {
                        std::cerr << "Failed to process interface configuration in section " << section_name << std::endl;
                        return false;
                    }
                }
            }
            
            // Process general action rules (catch-all rules)
            if (section.action) {
                if (!processActionConfig(*section.action, section_name)) {
                    std::cerr << "Failed to process action configuration in section " << section_name << std::endl;
                    return false;
                }
            }
        }
        
        std::cout << "Configuration processing completed" << std::endl;
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "Error loading configuration: " << e.what() << std::endl;
        return false;
    }
}

bool IptablesManager::processFilterConfig(const FilterConfig& filter) {
    std::cout << "Processing filter configuration" << std::endl;
    
    bool success = true;
    
    // Set default policies if specified
    if (filter.input) {
        std::cout << "Setting INPUT policy to: " << policyToString(*filter.input) << std::endl;
        
        // Generate comment for this policy rule
        std::string comment = "YAML:filter:input:" + getInterfaceComment(std::nullopt);
        
        // Remove existing rules with this signature (policies don't have rules to remove, but we clean up any custom rules)
        removeRulesBySignature("filter", "INPUT", comment);
        
        // Set the policy using CommandExecutor
        auto result = CommandExecutor::setChainPolicy("filter", "INPUT", policyToString(*filter.input));
        if (!result.isSuccess()) {
            std::cerr << "Failed to set INPUT policy: " << result.getErrorMessage() << std::endl;
            success = false;
        }
    }
    
    if (filter.output) {
        std::cout << "Setting OUTPUT policy to: " << policyToString(*filter.output) << std::endl;
        
        std::string comment = "YAML:filter:output:" + getInterfaceComment(std::nullopt);
        removeRulesBySignature("filter", "OUTPUT", comment);
        
        auto result = CommandExecutor::setChainPolicy("filter", "OUTPUT", policyToString(*filter.output));
        if (!result.isSuccess()) {
            std::cerr << "Failed to set OUTPUT policy: " << result.getErrorMessage() << std::endl;
            success = false;
        }
    }
    
    if (filter.forward) {
        std::cout << "Setting FORWARD policy to: " << policyToString(*filter.forward) << std::endl;
        
        std::string comment = "YAML:filter:forward:" + getInterfaceComment(std::nullopt);
        removeRulesBySignature("filter", "FORWARD", comment);
        
        auto result = CommandExecutor::setChainPolicy("filter", "FORWARD", policyToString(*filter.forward));
        if (!result.isSuccess()) {
            std::cerr << "Failed to set FORWARD policy: " << result.getErrorMessage() << std::endl;
            success = false;
        }
    }
    
    // Process MAC rules in filter section
    if (filter.mac) {
        for (const auto& mac : *filter.mac) {
            if (!processMacConfig(mac, "filter")) {
                std::cerr << "Failed to process MAC configuration in filter section" << std::endl;
                success = false;
            }
        }
    }
    
    return success;
}

bool IptablesManager::processPortConfig(const PortConfig& port, const std::string& section_name) {
    std::cout << "Processing port configuration for section: " << section_name << std::endl;
    std::cout << "  Port: " << port.port << std::endl;
    std::cout << "  Direction: " << static_cast<int>(port.direction) << std::endl;
    std::cout << "  Allow: " << (port.allow ? "true" : "false") << std::endl;
    std::cout << "  Protocol: " << static_cast<int>(port.protocol) << std::endl;
    
    if (port.interface) {
        if (port.interface->input) {
            std::cout << "  Input interface: " << *port.interface->input << std::endl;
        }
        if (port.interface->output) {
            std::cout << "  Output interface: " << *port.interface->output << std::endl;
        }
    }
    
    if (port.subnet) {
        std::cout << "  Subnets: ";
        for (const auto& subnet : *port.subnet) {
            std::cout << subnet << " ";
        }
        std::cout << std::endl;
    }
    
    if (port.mac_source) {
        std::cout << "  MAC source: " << *port.mac_source << std::endl;
    }
    
    if (port.forward) {
        std::cout << "  Forward port: " << *port.forward << std::endl;
    }
    
    // Generate rule comment
    std::string iface_comment = getInterfaceComment(port.interface);
    std::string mac_comment = port.mac_source.value_or("any");
    
    if (port.forward) {
        // Handle port forwarding in NAT table
        std::string comment = "YAML:" + section_name + ":port:" + std::to_string(port.port) + ":forward:" + iface_comment + ":mac:" + mac_comment;
        
        // Remove existing rules with this signature
        removeRulesBySignature("nat", "PREROUTING", comment);
        
        // Build iptables command for port forwarding
        std::vector<std::string> args = {"-t", "nat", "-A", "PREROUTING"};
        
        // Add interface specifications if present
        if (port.interface) {
            if (port.interface->input) {
                args.push_back("-i");
                args.push_back(*port.interface->input);
            }
            if (port.interface->output) {
                args.push_back("-o");
                args.push_back(*port.interface->output);
            }
        }
        
        // Add MAC source if specified
        if (port.mac_source) {
            args.push_back("-m");
            args.push_back("mac");
            args.push_back("--mac-source");
            args.push_back(*port.mac_source);
        }
        
        // Add protocol and port
        std::string protocol_str = (port.protocol == Protocol::Tcp) ? "tcp" : "udp";
        args.insert(args.end(), {
            "-p", protocol_str,
            "-m", protocol_str,
            "--dport", std::to_string(port.port),
            "-m", "comment",
            "--comment", comment,
            "-j", "REDIRECT",
            "--to-port", std::to_string(*port.forward)
        });
        
        auto result = CommandExecutor::executeIptables(args);
        if (!result.isSuccess()) {
            std::cerr << "Failed to add port forwarding rule: " << result.getErrorMessage() << std::endl;
            return false;
        }
        
    } else {
        // Handle regular rules in the specified chain
        std::string comment = "YAML:" + section_name + ":port:" + std::to_string(port.port) + ":" + iface_comment + ":mac:" + mac_comment;
        
        // Convert direction to chain name
        std::string chain;
        switch (port.direction) {
            case Direction::Input:
                chain = "INPUT";
                break;
            case Direction::Output:
                chain = "OUTPUT";
                break;
            case Direction::Forward:
                chain = "FORWARD";
                break;
        }
        
        // Remove existing rules with this signature
        removeRulesBySignature("filter", chain, comment);
        
        // Build iptables command for regular rule
        std::vector<std::string> args = {"-A", chain};
        
        // Add interface specifications if present
        if (port.interface) {
            if (port.interface->input) {
                args.push_back("-i");
                args.push_back(*port.interface->input);
            }
            if (port.interface->output) {
                args.push_back("-o");
                args.push_back(*port.interface->output);
            }
        }
        
        // Add MAC source if specified
        if (port.mac_source) {
            args.push_back("-m");
            args.push_back("mac");
            args.push_back("--mac-source");
            args.push_back(*port.mac_source);
        }
        
        // Add subnets if specified
        if (port.subnet && !port.subnet->empty()) {
            args.push_back("-s");
            std::ostringstream subnet_list;
            for (size_t i = 0; i < port.subnet->size(); ++i) {
                if (i > 0) subnet_list << ",";
                subnet_list << (*port.subnet)[i];
            }
            args.push_back(subnet_list.str());
        }
        
        // Add protocol and port
        std::string protocol_str = (port.protocol == Protocol::Tcp) ? "tcp" : "udp";
        args.insert(args.end(), {
            "-p", protocol_str,
            "-m", protocol_str,
            "--dport", std::to_string(port.port),
            "-m", "comment",
            "--comment", comment,
            "-j", port.allow ? "ACCEPT" : "DROP"
        });
        
        auto result = CommandExecutor::executeIptables(args);
        if (!result.isSuccess()) {
            std::cerr << "Failed to add port rule: " << result.getErrorMessage() << std::endl;
            return false;
        }
    }
    
    return true;
}

bool IptablesManager::processMacConfig(const MacConfig& mac, const std::string& section_name) {
    std::cout << "Processing MAC configuration for section: " << section_name << std::endl;
    std::cout << "  MAC source: " << mac.mac_source << std::endl;
    std::cout << "  Direction: " << static_cast<int>(mac.direction) << std::endl;
    std::cout << "  Allow: " << (mac.allow ? "true" : "false") << std::endl;
    
    if (mac.interface) {
        if (mac.interface->input) {
            std::cout << "  Input interface: " << *mac.interface->input << std::endl;
        }
        if (mac.interface->output) {
            std::cout << "  Output interface: " << *mac.interface->output << std::endl;
        }
    }
    
    if (mac.subnet) {
        std::cout << "  Subnets: ";
        for (const auto& subnet : *mac.subnet) {
            std::cout << subnet << " ";
        }
        std::cout << std::endl;
    }
    
    // Validate direction - only INPUT is allowed for MAC rules
    if (mac.direction != Direction::Input) {
        std::cerr << "MAC rules are only allowed in INPUT direction. Found direction: " << static_cast<int>(mac.direction) << std::endl;
        return false;
    }
    
    // Generate rule comment
    std::string iface_comment;
    if (mac.interface) {
        iface_comment = "i:" + mac.interface->input.value_or("any") + ":o:any";
    } else {
        iface_comment = "i:any:o:any";
    }
    std::string comment = "YAML:" + section_name + ":mac:" + mac.mac_source + ":" + iface_comment;
    
    // Remove existing rules with this signature
    removeRulesBySignature("filter", "INPUT", comment);
    
    // Build iptables command for MAC rule
    std::vector<std::string> args = {"-A", "INPUT"};
    
    // Add input interface if specified
    if (mac.interface && mac.interface->input) {
        args.push_back("-i");
        args.push_back(*mac.interface->input);
    }
    
    // Add MAC source
    args.insert(args.end(), {
        "-m", "mac",
        "--mac-source", mac.mac_source
    });
    
    // Add subnets if specified
    if (mac.subnet && !mac.subnet->empty()) {
        args.push_back("-s");
        std::ostringstream subnet_list;
        for (size_t i = 0; i < mac.subnet->size(); ++i) {
            if (i > 0) subnet_list << ",";
            subnet_list << (*mac.subnet)[i];
        }
        args.push_back(subnet_list.str());
    }
    
    // Add comment and action
    args.insert(args.end(), {
        "-m", "comment",
        "--comment", comment,
        "-j", mac.allow ? "ACCEPT" : "DROP"
    });
    
    auto result = CommandExecutor::executeIptables(args);
    if (!result.isSuccess()) {
        std::cerr << "Failed to add MAC rule: " << result.getErrorMessage() << std::endl;
        return false;
    }
    
    return true;
}

bool IptablesManager::processInterfaceConfig(const InterfaceRuleConfig& interface, const std::string& section_name) {
    std::cout << "Processing interface configuration for section: " << section_name << std::endl;
    std::cout << "  Direction: " << static_cast<int>(interface.direction) << std::endl;
    std::cout << "  Allow: " << (interface.allow ? "true" : "false") << std::endl;
    
    if (interface.input) {
        std::cout << "  Input interface: " << *interface.input << std::endl;
    }
    if (interface.output) {
        std::cout << "  Output interface: " << *interface.output << std::endl;
    }
    
    // Generate rule comment
    std::string iface_comment = "i:" + interface.input.value_or("any") + ":o:" + interface.output.value_or("any");
    std::string comment = "YAML:" + section_name + ":interface:" + iface_comment;
    
    // Convert direction to chain name
    std::string chain;
    switch (interface.direction) {
        case Direction::Input:
            chain = "INPUT";
            break;
        case Direction::Output:
            chain = "OUTPUT";
            break;
        case Direction::Forward:
            chain = "FORWARD";
            break;
    }
    
    // Remove existing rules with this signature
    removeRulesBySignature("filter", chain, comment);
    
    // Build iptables command for interface rule
    std::vector<std::string> args = {"-A", chain};
    
    // Add interface specifications if present
    if (interface.input) {
        args.push_back("-i");
        args.push_back(*interface.input);
    }
    if (interface.output) {
        args.push_back("-o");
        args.push_back(*interface.output);
    }
    
    // Add comment and action
    args.insert(args.end(), {
        "-m", "comment",
        "--comment", comment,
        "-j", interface.allow ? "ACCEPT" : "DROP"
    });
    
    auto result = CommandExecutor::executeIptables(args);
    if (!result.isSuccess()) {
        std::cerr << "Failed to add interface rule: " << result.getErrorMessage() << std::endl;
        return false;
    }
    
    return true;
}

bool IptablesManager::processActionConfig(const Action& action, const std::string& section_name) {
    std::cout << "Processing action configuration for section: " << section_name << std::endl;
    std::cout << "  Action: " << actionToString(action) << std::endl;
    
    // Generate rule comment for this catch-all rule
    std::string comment = "YAML:" + section_name + ":action:" + actionToString(action) + ":i:any:o:any:mac:any";
    
    // Remove existing rules with this signature
    removeRulesBySignature("filter", "INPUT", comment);
    
    // Build iptables command for the catch-all rule in INPUT chain
    std::vector<std::string> args = {"-A", "INPUT"};
    
    // Add comment
    args.insert(args.end(), {
        "-m", "comment",
        "--comment", comment,
        "-j", actionToString(action)
    });
    
    auto result = CommandExecutor::executeIptables(args);
    if (!result.isSuccess()) {
        std::cerr << "Failed to add action rule for section " << section_name 
                 << ": " << result.getErrorMessage() << std::endl;
        return false;
    }
    
    std::cout << "Successfully added action rule: " << actionToString(action) << " for section " << section_name << std::endl;
    return true;
}

bool IptablesManager::resetRules() {
    std::cout << "Resetting all iptables rules" << std::endl;
    
    // Define the reset commands (matching Rust implementation)
    std::vector<std::vector<std::string>> commands = {
        {"-F"},                    // Flush filter table
        {"-X"},                    // Delete user-defined chains in filter table
        {"-t", "nat", "-F"},       // Flush nat table
        {"-t", "nat", "-X"},       // Delete user-defined chains in nat table
        {"-t", "mangle", "-F"},    // Flush mangle table
        {"-t", "mangle", "-X"}     // Delete user-defined chains in mangle table
    };
    
    bool success = true;
    
    for (const auto& cmd : commands) {
        auto result = CommandExecutor::executeIptables(cmd);
        if (!result.isSuccess()) {
            std::cerr << "Failed to execute reset command: " << result.getErrorMessage() << std::endl;
            success = false;
        }
    }
    
    if (success) {
        std::cout << "Successfully reset all iptables rules" << std::endl;
    }
    
    return success;
}

bool IptablesManager::removeYamlRules() {
    std::cout << "Removing all rules with YAML comments" << std::endl;
    
    // Define chains with their respective tables (matching Rust implementation)
    std::vector<std::pair<std::string, std::string>> chains = {
        {"filter", "INPUT"},
        {"filter", "OUTPUT"},
        {"filter", "FORWARD"},
        {"nat", "PREROUTING"},
        {"nat", "POSTROUTING"}
    };
    
    bool success = true;
    
    for (const auto& [table, chain] : chains) {
        // List rules with line numbers
        std::vector<std::string> cmd_args = {"-t", table, "-L", chain, "--line-numbers"};
        auto result = CommandExecutor::executeIptables(cmd_args);
        
        if (!result.isSuccess()) {
            // Chain might not exist, skip
            continue;
        }
        
        // Collect line numbers of rules with YAML comments
        std::vector<uint32_t> yaml_rule_lines;
        std::istringstream iss(result.stdout_output);
        std::string line;
        
        while (std::getline(iss, line)) {
            if (line.find("YAML:") != std::string::npos) {
                // Extract line number (first token)
                std::istringstream line_stream(line);
                std::string line_num_str;
                if (line_stream >> line_num_str) {
                    try {
                        uint32_t line_num = std::stoul(line_num_str);
                        yaml_rule_lines.push_back(line_num);
                    } catch (const std::exception&) {
                        // Not a number, skip
                    }
                }
            }
        }
        
        // Sort line numbers in descending order to delete from bottom to top
        std::sort(yaml_rule_lines.begin(), yaml_rule_lines.end(), std::greater<uint32_t>());
        
        // Delete rules from highest to lowest line number
        for (uint32_t line_num : yaml_rule_lines) {
            auto del_result = CommandExecutor::removeRuleByLineNumber(table, chain, line_num);
            if (!del_result.isSuccess()) {
                std::cerr << "Failed to remove rule at line " << line_num << " in " << table << "." << chain 
                         << ": " << del_result.getErrorMessage() << std::endl;
                success = false;
            }
        }
    }
    
    // Reset policies to ACCEPT after removing rules (matching Rust implementation)
    auto input_policy = CommandExecutor::setChainPolicy("filter", "INPUT", "ACCEPT");
    auto output_policy = CommandExecutor::setChainPolicy("filter", "OUTPUT", "ACCEPT");
    auto forward_policy = CommandExecutor::setChainPolicy("filter", "FORWARD", "ACCEPT");
    
    if (!input_policy.isSuccess() || !output_policy.isSuccess() || !forward_policy.isSuccess()) {
        std::cerr << "Warning: Failed to reset some policies to ACCEPT" << std::endl;
        success = false;
    }
    
    if (success) {
        std::cout << "Successfully removed all rules with YAML comments" << std::endl;
    }
    
    return success;
}

bool IptablesManager::applyRules() {
    return rule_manager_.applyRules();
}

bool IptablesManager::removeAllRules() {
    return rule_manager_.removeAllRules();
}

bool IptablesManager::setPolicy(Direction direction, Action action) {
    return rule_manager_.setPolicy(direction, action);
}

bool IptablesManager::resetPolicies() {
    return rule_manager_.resetPolicies();
}

// Helper methods
Direction IptablesManager::parseDirection(const std::string& direction) {
    std::string lower_dir = direction;
    std::transform(lower_dir.begin(), lower_dir.end(), lower_dir.begin(), ::tolower);
    
    if (lower_dir == "input" || lower_dir == "in") {
        return Direction::Input;
    } else if (lower_dir == "output" || lower_dir == "out") {
        return Direction::Output;
    } else if (lower_dir == "forward" || lower_dir == "fwd") {
        return Direction::Forward;
    } else {
        // Default to Input if unknown
        std::cerr << "Warning: Unknown direction '" << direction << "', defaulting to Input" << std::endl;
        return Direction::Input;
    }
}

Action IptablesManager::parseAction(const std::string& action) {
    std::string lower_action = action;
    std::transform(lower_action.begin(), lower_action.end(), lower_action.begin(), ::tolower);
    
    if (lower_action == "accept" || lower_action == "allow") {
        return Action::Accept;
    } else if (lower_action == "drop" || lower_action == "deny") {
        return Action::Drop;
    } else if (lower_action == "reject") {
        return Action::Reject;
    } else {
        // Default to Accept if unknown
        std::cerr << "Warning: Unknown action '" << action << "', defaulting to Accept" << std::endl;
        return Action::Accept;
    }
}

Protocol IptablesManager::parseProtocol(const std::string& protocol) {
    std::string lower_protocol = protocol;
    std::transform(lower_protocol.begin(), lower_protocol.end(), lower_protocol.begin(), ::tolower);
    
    if (lower_protocol == "tcp") {
        return Protocol::Tcp;
    } else if (lower_protocol == "udp") {
        return Protocol::Udp;
    } else {
        // Default to TCP if unknown
        std::cerr << "Warning: Unknown protocol '" << protocol << "', defaulting to TCP" << std::endl;
        return Protocol::Tcp;
    }
}

InterfaceConfig IptablesManager::parseInterface(const YAML::Node& node) {
    InterfaceConfig config;
    
    if (!node) {
        return config; // Return empty interface config
    }
    
    try {
        // Handle different YAML node types
        if (node.IsScalar()) {
            // Single interface string - treat as input interface
            std::string interface = node.as<std::string>();
            if (!interface.empty() && interface != "any") {
                config.input = interface;
            }
        } else if (node.IsMap()) {
            // Interface object with input/output fields
            if (node["input"]) {
                std::string input_iface = node["input"].as<std::string>();
                if (!input_iface.empty() && input_iface != "any") {
                    config.input = input_iface;
                }
            }
            if (node["output"]) {
                std::string output_iface = node["output"].as<std::string>();
                if (!output_iface.empty() && output_iface != "any") {
                    config.output = output_iface;
                }
            }
            
            // Handle legacy "in" and "out" field names for compatibility
            if (node["in"]) {
                std::string input_iface = node["in"].as<std::string>();
                if (!input_iface.empty() && input_iface != "any") {
                    config.input = input_iface;
                }
            }
            if (node["out"]) {
                std::string output_iface = node["out"].as<std::string>();
                if (!output_iface.empty() && output_iface != "any") {
                    config.output = output_iface;
                }
            }
        }
    } catch (const YAML::Exception& e) {
        std::cerr << "Warning: Failed to parse interface configuration: " << e.what() << std::endl;
    }
    
    return config;
}

} // namespace iptables 