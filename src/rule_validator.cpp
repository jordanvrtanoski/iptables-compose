#include "rule_validator.hpp"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <arpa/inet.h>
#include <functional>

namespace iptables {

std::vector<ValidationWarning> RuleValidator::validateRuleOrder(const Config& config) {
    std::vector<ValidationWarning> warnings;
    
    // Extract all rules with their selectivity for analysis
    auto rules = extractRuleSelectivity(config);
    
    // Check each rule against all previous rules
    for (size_t i = 0; i < rules.size(); ++i) {
        for (size_t j = 0; j < i; ++j) {
            const auto& earlier_rule = rules[j];
            const auto& later_rule = rules[i];
            
            // Check if the earlier rule makes the later rule unreachable
            if (isRuleUnreachable(earlier_rule, later_rule)) {
                ValidationWarning warning;
                warning.type = ValidationWarning::Type::UnreachableRule;
                warning.section_name = later_rule.section_name;
                warning.rule_index = later_rule.rule_index;
                warning.conflicting_section = earlier_rule.section_name;
                warning.conflicting_rule_index = earlier_rule.rule_index;
                
                std::ostringstream msg;
                msg << "Rule will never be executed: " << later_rule.rule_description
                    << " in section '" << later_rule.section_name << "' (rule #" << (later_rule.rule_index + 1) << ")"
                    << " is overshadowed by " << earlier_rule.rule_description
                    << " in section '" << earlier_rule.section_name << "' (rule #" << (earlier_rule.rule_index + 1) << ")";
                warning.message = msg.str();
                
                warnings.push_back(warning);
            }
        }
    }
    
    return warnings;
}

bool RuleValidator::isRuleUnreachable(const RuleSelectivity& rule_a, const RuleSelectivity& rule_b) {
    // Rule B is unreachable if:
    // 1. Rule A's conditions are a superset of Rule B's conditions, AND
    // 2. Rule A has a blocking action (DROP/REJECT) while Rule B has ACCEPT, OR
    //    Rule A has ACCEPT while Rule B has DROP/REJECT (redundant rule)
    
    // Check if rule_a's selectivity covers rule_b's selectivity
    
    // 1. Check subnet containment
    if (rule_a.subnets && rule_b.subnets) {
        // Check if all of rule_b's subnets are contained in rule_a's subnets
        bool all_contained = true;
        for (const auto& subnet_b : *rule_b.subnets) {
            bool contained_in_any = false;
            for (const auto& subnet_a : *rule_a.subnets) {
                if (subnetContains(subnet_a, subnet_b)) {
                    contained_in_any = true;
                    break;
                }
            }
            if (!contained_in_any) {
                all_contained = false;
                break;
            }
        }
        if (!all_contained) return false;
    } else if (rule_b.subnets && !rule_a.subnets) {
        // rule_a has no subnet restriction (matches all), rule_b has restrictions
        // rule_a is more general, continue checking
    } else if (rule_a.subnets && !rule_b.subnets) {
        // rule_a has subnet restrictions, rule_b has none
        // rule_b is more general, so rule_a doesn't overshadow rule_b
        return false;
    }
    // If both have no subnet restrictions, they overlap in this dimension
    
    // 2. Check port specificity
    if (rule_a.port && rule_b.port) {
        if (*rule_a.port != *rule_b.port) {
            return false; // Different ports, no overlap
        }
    } else if (rule_b.port && !rule_a.port) {
        // rule_a matches any port, rule_b matches specific port
        // rule_a is more general, continue checking
    } else if (rule_a.port && !rule_b.port) {
        // rule_a matches specific port, rule_b matches any port
        // rule_b is more general, so rule_a doesn't overshadow rule_b
        return false;
    }
    // If both have no port restrictions, they overlap in this dimension
    
    // 3. Check protocol
    if (rule_a.protocol != rule_b.protocol) {
        return false; // Different protocols, no overlap
    }
    
    // 4. Check interface specificity
    if (!isInterfaceMoreSpecific(rule_b.input_interface, rule_a.input_interface)) {
        return false; // rule_a is not more general in input interface
    }
    if (!isInterfaceMoreSpecific(rule_b.output_interface, rule_a.output_interface)) {
        return false; // rule_a is not more general in output interface
    }
    
    // 5. Check MAC address specificity
    if (rule_a.mac_source && rule_b.mac_source) {
        if (*rule_a.mac_source != *rule_b.mac_source) {
            return false; // Different MAC addresses, no overlap
        }
    } else if (rule_b.mac_source && !rule_a.mac_source) {
        // rule_a matches any MAC, rule_b matches specific MAC
        // rule_a is more general, continue checking
    } else if (rule_a.mac_source && !rule_b.mac_source) {
        // rule_a matches specific MAC, rule_b matches any MAC
        // rule_b is more general, so rule_a doesn't overshadow rule_b
        return false;
    }
    
    // If we reach here, rule_a's conditions are a superset of rule_b's conditions
    
    // 6. Check if this creates a problematic situation
    if (!rule_a.allow && rule_b.allow) {
        // rule_a blocks traffic that rule_b would allow - rule_b is unreachable
        return true;
    }
    
    if (rule_a.allow && !rule_b.allow) {
        // rule_a allows traffic that rule_b would block - rule_b is redundant
        return true;
    }
    
    if (rule_a.allow == rule_b.allow) {
        // Both have same action - rule_b is redundant
        return true;
    }
    
    return false;
}

bool RuleValidator::subnetContains(const std::string& subnet_a, const std::string& subnet_b) {
    try {
        auto [net_a, prefix_a] = parseCIDR(subnet_a);
        auto [net_b, prefix_b] = parseCIDR(subnet_b);
        
        // subnet_a contains subnet_b if:
        // 1. subnet_a has smaller or equal prefix (less specific or equally specific)
        // 2. subnet_b's network address falls within subnet_a's range
        
        if (prefix_a > prefix_b) {
            return false; // subnet_a is more specific than subnet_b
        }
        
        // Create mask for subnet_a
        uint32_t mask_a = (prefix_a == 0) ? 0 : (~0U << (32 - prefix_a));
        
        // Check if subnet_b's network falls within subnet_a
        return (net_a & mask_a) == (net_b & mask_a);
        
    } catch (const std::exception&) {
        // If parsing fails, assume no containment
        return false;
    }
}

std::vector<RuleSelectivity> RuleValidator::extractRuleSelectivity(const Config& config) {
    std::vector<RuleSelectivity> rules;
    
    // Extract from filter section MAC rules first (they're processed first)
    if (config.filter && config.filter->mac) {
        for (size_t i = 0; i < config.filter->mac->size(); ++i) {
            const auto& mac = (*config.filter->mac)[i];
            rules.push_back(extractMacSelectivity(mac, "filter", i));
        }
    }
    
    // Extract from custom sections in order
    for (const auto& [section_name, section] : config.custom_sections) {
        size_t rule_index = 0;
        
        // Process port rules first
        if (section.ports) {
            for (size_t i = 0; i < section.ports->size(); ++i) {
                const auto& port = (*section.ports)[i];
                rules.push_back(extractPortSelectivity(port, section_name, rule_index++));
            }
        }
        
        // Process MAC rules second
        if (section.mac) {
            for (size_t i = 0; i < section.mac->size(); ++i) {
                const auto& mac = (*section.mac)[i];
                rules.push_back(extractMacSelectivity(mac, section_name, rule_index++));
            }
        }
        
        // Interface rules would go here if implemented
    }
    
    return rules;
}

RuleSelectivity RuleValidator::extractPortSelectivity(const PortConfig& port, const std::string& section, size_t index) {
    RuleSelectivity selectivity;
    
    selectivity.subnets = port.subnet;
    selectivity.protocol = port.protocol;
    selectivity.mac_source = port.mac_source;
    selectivity.allow = port.allow;
    selectivity.section_name = section;
    selectivity.rule_index = index;
    
    // Handle single port or port ranges
    if (port.port) {
        selectivity.port = static_cast<int>(*port.port);
    }
    if (port.range) {
        selectivity.port_ranges = port.range;
    }
    
    if (port.interface) {
        selectivity.input_interface = port.interface->input;
        selectivity.output_interface = port.interface->output;
    }
    
    std::ostringstream desc;
    if (port.port) {
        desc << "port " << *port.port;
    } else if (port.range) {
        desc << "port ranges [";
        for (size_t i = 0; i < port.range->size(); ++i) {
            if (i > 0) desc << ", ";
            desc << (*port.range)[i];
        }
        desc << "]";
    }
    desc << " (" << (port.protocol == Protocol::Tcp ? "TCP" : "UDP") << ")";
    
    if (port.subnet) {
        desc << " from subnets: ";
        for (size_t i = 0; i < port.subnet->size(); ++i) {
            if (i > 0) desc << ", ";
            desc << (*port.subnet)[i];
        }
    }
    desc << " -> " << (port.allow ? "ACCEPT" : "DROP");
    selectivity.rule_description = desc.str();
    
    return selectivity;
}

RuleSelectivity RuleValidator::extractMacSelectivity(const MacConfig& mac, const std::string& section, size_t index) {
    RuleSelectivity selectivity;
    
    selectivity.subnets = mac.subnet;
    selectivity.mac_source = mac.mac_source;
    selectivity.allow = mac.allow;
    selectivity.section_name = section;
    selectivity.rule_index = index;
    selectivity.protocol = Protocol::Tcp; // MAC rules apply to all protocols
    
    if (mac.interface) {
        selectivity.input_interface = mac.interface->input;
        selectivity.output_interface = mac.interface->output;
    }
    
    std::ostringstream desc;
    desc << "MAC " << mac.mac_source;
    if (mac.subnet) {
        desc << " from subnets: ";
        for (size_t i = 0; i < mac.subnet->size(); ++i) {
            if (i > 0) desc << ", ";
            desc << (*mac.subnet)[i];
        }
    }
    desc << " -> " << (mac.allow ? "ACCEPT" : "DROP");
    selectivity.rule_description = desc.str();
    
    return selectivity;
}

std::pair<uint32_t, int> RuleValidator::parseCIDR(const std::string& cidr) {
    size_t slash_pos = cidr.find('/');
    std::string ip_str;
    int prefix_len = 32; // Default to /32 if no prefix specified
    
    if (slash_pos != std::string::npos) {
        ip_str = cidr.substr(0, slash_pos);
        prefix_len = std::stoi(cidr.substr(slash_pos + 1));
    } else {
        ip_str = cidr;
    }
    
    struct in_addr addr;
    if (inet_aton(ip_str.c_str(), &addr) == 0) {
        throw std::runtime_error("Invalid IP address: " + ip_str);
    }
    
    uint32_t ip = ntohl(addr.s_addr);
    
    // Apply the network mask to get the network address
    if (prefix_len < 32) {
        uint32_t mask = (~0U << (32 - prefix_len));
        ip &= mask;
    }
    
    return {ip, prefix_len};
}

bool RuleValidator::isInterfaceMoreSpecific(const std::optional<std::string>& specific, 
                                          const std::optional<std::string>& general) {
    // Returns true if 'specific' is more specific than or equal to 'general'
    // This means 'general' would match 'specific' (general is broader or same)
    
    if (!general.has_value()) {
        // general matches any interface, so it covers specific
        return true;
    }
    
    if (!specific.has_value()) {
        // specific matches any interface, general matches specific interface
        // general is more specific, so general doesn't cover specific
        return false;
    }
    
    // Both have values - they must match exactly for general to cover specific
    return *general == *specific;
}

// ✨ NEW: Validate chain configurations and references
std::vector<ValidationWarning> RuleValidator::validateChainReferences(const Config& config) {
    std::vector<ValidationWarning> warnings;
    
    // Collect all defined chains
    std::set<std::string> defined_chains;
    for (const auto& [chain_name, chain_config] : config.chain_definitions) {
        if (chain_config.chain.empty()) {
            continue;
        }
        for (const auto& chain_rule : chain_config.chain) {
            defined_chains.insert(chain_rule.name);
        }
    }
    
    // Check chain references in sections
    for (const auto& [section_name, section] : config.custom_sections) {
        // Check interface config chain references
        if (section.interface_config && section.interface_config->chain) {
            const std::string& referenced_chain = *section.interface_config->chain;
            if (defined_chains.find(referenced_chain) == defined_chains.end()) {
                ValidationWarning warning;
                warning.type = ValidationWarning::Type::InvalidChainReference;
                warning.section_name = section_name;
                warning.rule_index = 0;
                warning.message = "Section '" + section_name + "' references undefined chain '" + referenced_chain + "'";
                warnings.push_back(warning);
            }
        }
        
        // Check port config direct chain references
        if (section.ports) {
            for (size_t i = 0; i < section.ports->size(); ++i) {
                const auto& port = (*section.ports)[i];
                if (port.chain) {
                    const std::string& referenced_chain = *port.chain;
                    if (defined_chains.find(referenced_chain) == defined_chains.end()) {
                        ValidationWarning warning;
                        warning.type = ValidationWarning::Type::InvalidChainReference;
                        warning.section_name = section_name;
                        warning.rule_index = i;
                        warning.message = "Port rule in section '" + section_name + "' references undefined chain '" + referenced_chain + "'";
                        warnings.push_back(warning);
                    }
                }
                
                // Also check interface chain references within port rules
                if (port.interface && port.interface->chain) {
                    const std::string& referenced_chain = *port.interface->chain;
                    if (defined_chains.find(referenced_chain) == defined_chains.end()) {
                        ValidationWarning warning;
                        warning.type = ValidationWarning::Type::InvalidChainReference;
                        warning.section_name = section_name;
                        warning.rule_index = i;
                        warning.message = "Port rule interface in section '" + section_name + "' references undefined chain '" + referenced_chain + "'";
                        warnings.push_back(warning);
                    }
                }
            }
        }
        
        // Check MAC config direct chain references
        if (section.mac) {
            for (size_t i = 0; i < section.mac->size(); ++i) {
                const auto& mac = (*section.mac)[i];
                if (mac.chain) {
                    const std::string& referenced_chain = *mac.chain;
                    if (defined_chains.find(referenced_chain) == defined_chains.end()) {
                        ValidationWarning warning;
                        warning.type = ValidationWarning::Type::InvalidChainReference;
                        warning.section_name = section_name;
                        warning.rule_index = i;
                        warning.message = "MAC rule in section '" + section_name + "' references undefined chain '" + referenced_chain + "'";
                        warnings.push_back(warning);
                    }
                }
                
                // Also check interface chain references within MAC rules
                if (mac.interface && mac.interface->chain) {
                    const std::string& referenced_chain = *mac.interface->chain;
                    if (defined_chains.find(referenced_chain) == defined_chains.end()) {
                        ValidationWarning warning;
                        warning.type = ValidationWarning::Type::InvalidChainReference;
                        warning.section_name = section_name;
                        warning.rule_index = i;
                        warning.message = "MAC rule interface in section '" + section_name + "' references undefined chain '" + referenced_chain + "'";
                        warnings.push_back(warning);
                    }
                }
            }
        }
    }
    
    // Check for circular dependencies
    if (hasCircularChainDependencies(config)) {
        ValidationWarning warning;
        warning.type = ValidationWarning::Type::CircularChainDependency;
        warning.section_name = "global";
        warning.rule_index = 0;
        warning.message = "Circular chain dependencies detected in configuration";
        warnings.push_back(warning);
    }
    
    return warnings;
}

// ✨ NEW: Validate individual port rule for chain vs. action mutual exclusivity
std::optional<ValidationWarning> RuleValidator::validatePortConfigChains(
    const PortConfig& port_config, 
    const std::string& section_name, 
    size_t rule_index) {
    
    // Check if both direct chain and action are specified
    bool has_direct_chain = port_config.chain.has_value();
    bool has_forward = port_config.forward.has_value();
    
    if (has_direct_chain && has_forward) {
        ValidationWarning warning;
        warning.type = ValidationWarning::Type::ChainActionConflict;
        warning.section_name = section_name;
        warning.rule_index = rule_index;
        warning.message = "Port rule cannot have both chain target and port forwarding";
        return warning;
    }
    
    // Check if both chain and action are specified through interface config
    bool has_interface_chain = port_config.interface && port_config.interface->chain.has_value();
    
    if (has_interface_chain && has_forward) {
        ValidationWarning warning;
        warning.type = ValidationWarning::Type::ChainActionConflict;
        warning.section_name = section_name;
        warning.rule_index = rule_index;
        warning.message = "Port rule cannot have both interface chain reference and port forwarding";
        return warning;
    }
    
    return std::nullopt;
}

// ✨ NEW: Validate MAC rule for chain vs. action mutual exclusivity
std::optional<ValidationWarning> RuleValidator::validateMacConfigChains(
    const MacConfig& mac_config, 
    const std::string& section_name, 
    size_t rule_index) {
    
    // Check if both direct chain and action are specified
    bool has_direct_chain = mac_config.chain.has_value();
    
    // For MAC rules, we don't need to check allow since it's always present
    // The conflict is only if both chain and allow=false are specified
    // But since allow is always present, we only check for chain conflicts with interface chains
    
    // Check if both chain and action are specified through interface config
    bool has_interface_chain = mac_config.interface && mac_config.interface->chain.has_value();
    
    // MAC rules with direct chain targets are valid - no conflict to check
    // The conflict would be at the rule generation level, not validation level
    
    return std::nullopt;
}

// ✨ NEW: Check for circular chain dependencies
bool RuleValidator::hasCircularChainDependencies(const Config& config) {
    // Build dependency graph
    std::map<std::string, std::set<std::string>> dependencies;
    
    // Collect all defined chains first
    std::set<std::string> defined_chains;
    for (const auto& [chain_name, chain_config] : config.chain_definitions) {
        if (chain_config.chain.empty()) {
            continue;
        }
        for (const auto& chain_rule : chain_config.chain) {
            defined_chains.insert(chain_rule.name);
            dependencies[chain_rule.name] = std::set<std::string>();
        }
    }
    
    // Collect chain dependencies from chain definitions
    for (const auto& [chain_name, chain_config] : config.chain_definitions) {
        if (chain_config.chain.empty()) {
            continue;
        }
        for (const auto& chain_rule : chain_config.chain) {
            const std::string& current_chain = chain_rule.name;
            
            // Check dependencies in chain rules
            for (const auto& [rule_name, rule_config] : chain_rule.rules) {
                // Check interface chain calls
                if (rule_config.interface_config && rule_config.interface_config->chain) {
                    const std::string& referenced_chain = *rule_config.interface_config->chain;
                    if (defined_chains.find(referenced_chain) != defined_chains.end()) {
                        dependencies[current_chain].insert(referenced_chain);
                    }
                }
                
                // Check port config chain references
                if (rule_config.ports) {
                    for (const auto& port : *rule_config.ports) {
                        if (port.chain) {
                            const std::string& referenced_chain = *port.chain;
                            if (defined_chains.find(referenced_chain) != defined_chains.end()) {
                                dependencies[current_chain].insert(referenced_chain);
                            }
                        }
                        if (port.interface && port.interface->chain) {
                            const std::string& referenced_chain = *port.interface->chain;
                            if (defined_chains.find(referenced_chain) != defined_chains.end()) {
                                dependencies[current_chain].insert(referenced_chain);
                            }
                        }
                    }
                }
                
                // Check MAC config chain references
                if (rule_config.mac) {
                    for (const auto& mac : *rule_config.mac) {
                        if (mac.chain) {
                            const std::string& referenced_chain = *mac.chain;
                            if (defined_chains.find(referenced_chain) != defined_chains.end()) {
                                dependencies[current_chain].insert(referenced_chain);
                            }
                        }
                        if (mac.interface && mac.interface->chain) {
                            const std::string& referenced_chain = *mac.interface->chain;
                            if (defined_chains.find(referenced_chain) != defined_chains.end()) {
                                dependencies[current_chain].insert(referenced_chain);
                            }
                        }
                    }
                }
            }
        }
    }
    
    // Use DFS to detect cycles
    std::set<std::string> visiting;  // Currently being visited (gray nodes)
    std::set<std::string> visited;   // Already processed (black nodes)
    
    std::function<bool(const std::string&)> hasCycleDFS = [&](const std::string& chain) -> bool {
        if (visiting.find(chain) != visiting.end()) {
            // Found a back edge - cycle detected
            return true;
        }
        
        if (visited.find(chain) != visited.end()) {
            // Already processed this chain
            return false;
        }
        
        visiting.insert(chain);
        
        // Visit all dependencies
        if (dependencies.find(chain) != dependencies.end()) {
            for (const std::string& dependency : dependencies[chain]) {
                if (hasCycleDFS(dependency)) {
                    return true;
                }
            }
        }
        
        visiting.erase(chain);
        visited.insert(chain);
        return false;
    };
    
    // Check each chain for cycles
    for (const std::string& chain : defined_chains) {
        if (visited.find(chain) == visited.end()) {
            if (hasCycleDFS(chain)) {
                return true;
            }
        }
    }
    
    return false;
}

} // namespace iptables 