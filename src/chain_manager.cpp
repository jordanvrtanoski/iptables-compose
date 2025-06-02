#include "chain_manager.hpp"
#include <algorithm>
#include <sstream>
#include <queue>
#include <iostream>
#include <functional>

namespace iptables {

ChainManager::ChainManager(CommandExecutor& executor, bool debug_mode)
    : executor_(executor), debug_mode_(debug_mode) {
    clearError();
}

bool ChainManager::createChain(const std::string& chain_name) {
    clearError();
    
    if (chain_name.empty()) {
        setError("Chain name cannot be empty");
        return false;
    }
    
    // Check if chain already exists
    if (chainExists(chain_name)) {
        // Chain already exists, consider this success
        managed_chains_.insert(chain_name);
        return true;
    }
    
    // Create the chain
    CommandResult result = executor_.executeIptables({"-t", "filter", "-N", chain_name});
    
    if (!result.isSuccess()) {
        setError("Failed to create chain '" + chain_name + "': " + result.getErrorMessage());
        return false;
    }
    
    managed_chains_.insert(chain_name);
    return true;
}

bool ChainManager::deleteChain(const std::string& chain_name) {
    clearError();
    
    if (chain_name.empty()) {
        setError("Chain name cannot be empty");
        return false;
    }
    
    // Check if chain exists
    if (!chainExists(chain_name)) {
        // Chain doesn't exist, consider this success
        managed_chains_.erase(chain_name);
        return true;
    }
    
    // First flush the chain
    if (!flushChain(chain_name)) {
        return false;
    }
    
    // Then delete the chain
    CommandResult result = executor_.executeIptables({"-t", "filter", "-X", chain_name});
    
    if (!result.isSuccess()) {
        setError("Failed to delete chain '" + chain_name + "': " + result.getErrorMessage());
        return false;
    }
    
    managed_chains_.erase(chain_name);
    return true;
}

bool ChainManager::flushChain(const std::string& chain_name) {
    clearError();
    
    if (chain_name.empty()) {
        setError("Chain name cannot be empty");
        return false;
    }
    
    CommandResult result = executor_.executeIptables({"-t", "filter", "-F", chain_name});
    
    if (!result.isSuccess()) {
        setError("Failed to flush chain '" + chain_name + "': " + result.getErrorMessage());
        return false;
    }
    
    return true;
}

bool ChainManager::chainExists(const std::string& chain_name) {
    clearError();
    
    if (chain_name.empty()) {
        return false;
    }
    
    // Use iptables -L to check if chain exists
    CommandResult result = executor_.executeIptables({"-t", "filter", "-L", "-n"});
    
    if (!result.isSuccess()) {
        setError("Failed to list chains: " + result.getErrorMessage());
        return false;
    }
    
    std::istringstream iss(result.stdout_output);
    std::string line;
    while (std::getline(iss, line)) {
        if (line.find("Chain ") == 0) {
            size_t start = 6; // Length of "Chain "
            size_t end = line.find(" ", start);
            if (end != std::string::npos) {
                std::string chain_name_in_list = line.substr(start, end - start);
                // Skip built-in chains
                if (chain_name_in_list != "INPUT" && chain_name_in_list != "OUTPUT" && 
                    chain_name_in_list != "FORWARD" && chain_name_in_list != "PREROUTING" && 
                    chain_name_in_list != "POSTROUTING") {
                    if (chain_name == chain_name_in_list) {
                        return true;
                    }
                }
            }
        }
    }
    
    return false;
}

std::vector<std::string> ChainManager::listChains() {
    clearError();
    
    if (debug_mode_) {
        // In debug mode, return our managed chains
        return std::vector<std::string>(managed_chains_.begin(), managed_chains_.end());
    }
    
    CommandResult result = executor_.executeIptables({"-t", "filter", "-L", "-n"});
    
    if (!result.isSuccess()) {
        setError("Failed to list chains: " + result.getErrorMessage());
        return {};
    }
    
    std::vector<std::string> chains;
    std::istringstream iss(result.stdout_output);
    std::string line;
    while (std::getline(iss, line)) {
        if (line.find("Chain ") == 0) {
            size_t start = 6; // Length of "Chain "
            size_t end = line.find(" ", start);
            if (end != std::string::npos) {
                std::string chain_name = line.substr(start, end - start);
                // Skip built-in chains
                if (chain_name != "INPUT" && chain_name != "OUTPUT" && 
                    chain_name != "FORWARD" && chain_name != "PREROUTING" && 
                    chain_name != "POSTROUTING") {
                    chains.push_back(chain_name);
                }
            }
        }
    }
    
    return chains;
}

bool ChainManager::processChainConfigurations(const Config& config) {
    clearError();
    
    // First validate chain references
    if (!validateChainReferences(config)) {
        return false;
    }
    
    // Get creation order
    std::vector<std::string> creation_order = getChainCreationOrder(config);
    
    // Create chains in dependency order
    for (const std::string& chain_name : creation_order) {
        if (!createChain(chain_name)) {
            return false;
        }
    }
    
    return true;
}

std::vector<std::string> ChainManager::getChainCreationOrder(const Config& config) {
    std::map<std::string, std::set<std::string>> dependency_graph;
    buildDependencyGraph(config, dependency_graph);
    return topologicalSort(dependency_graph);
}

bool ChainManager::validateChainReferences(const Config& config) {
    clearError();
    
    // Build mapping from section names to actual chain names
    std::map<std::string, std::string> section_to_chain_map;
    std::set<std::string> defined_chains;
    
    for (const auto& [section_name, chain_config] : config.chain_definitions) {
        for (const auto& chain_rule : chain_config.chain) {
            defined_chains.insert(chain_rule.name);
            section_to_chain_map[section_name] = chain_rule.name;  // Map section name to chain name
            if (debug_mode_) {
                std::cout << "DEBUG: Found defined chain: " << chain_rule.name << " (section: " << section_name << ")" << std::endl;
            }
        }
    }
    
    if (debug_mode_) {
        std::cout << "DEBUG: Total chain_definitions sections: " << config.chain_definitions.size() << std::endl;
        std::cout << "DEBUG: Total custom_sections: " << config.custom_sections.size() << std::endl;
    }
    
    // Check all chain references in custom_sections
    std::set<std::string> referenced_chains;
    for (const auto& [section_name, section_config] : config.custom_sections) {
        extractChainReferences(section_config, referenced_chains);
    }
    
    if (debug_mode_) {
        std::cout << "DEBUG: Referenced chains: ";
        for (const auto& ref : referenced_chains) {
            std::cout << ref << " ";
        }
        std::cout << std::endl;
    }
    
    // Validate that all referenced chains are defined (check both section names and actual chain names)
    for (const std::string& referenced_chain : referenced_chains) {
        bool found = false;
        
        // Check if it's a section name that maps to a chain
        if (section_to_chain_map.find(referenced_chain) != section_to_chain_map.end()) {
            found = true;
            if (debug_mode_) {
                std::cout << "DEBUG: Found reference '" << referenced_chain << "' as section mapping to chain '" << section_to_chain_map[referenced_chain] << "'" << std::endl;
            }
        }
        // Also check if it's a direct chain name reference
        else if (defined_chains.find(referenced_chain) != defined_chains.end()) {
            found = true;
            if (debug_mode_) {
                std::cout << "DEBUG: Found reference '" << referenced_chain << "' as direct chain name" << std::endl;
            }
        }
        
        if (!found) {
            setError("Referenced chain '" + referenced_chain + "' is not defined");
            return false;
        }
    }
    
    // Check for circular dependencies
    std::map<std::string, std::set<std::string>> dependency_graph;
    buildDependencyGraph(config, dependency_graph);
    
    if (hasCycle(dependency_graph)) {
        setError("Circular dependency detected in chain references");
        return false;
    }
    
    return true;
}

bool ChainManager::cleanupChains() {
    clearError();
    
    bool success = true;
    
    // Get all custom chains (excluding built-in chains)
    std::vector<std::string> all_chains = listChains();
    
    if (debug_mode_) {
        std::cout << "DEBUG: Found " << all_chains.size() << " custom chains to clean up" << std::endl;
        for (const auto& chain : all_chains) {
            std::cout << "DEBUG: Will attempt to delete chain: " << chain << std::endl;
        }
    }
    
    // Delete all custom chains
    for (const std::string& chain_name : all_chains) {
        if (debug_mode_) {
            std::cout << "DEBUG: Deleting chain: " << chain_name << std::endl;
        }
        
        if (!deleteChain(chain_name)) {
            std::cerr << "Failed to delete chain: " << chain_name << " - " << getLastError() << std::endl;
            success = false;
            // Continue trying to delete other chains
        } else if (debug_mode_) {
            std::cout << "DEBUG: Successfully deleted chain: " << chain_name << std::endl;
        }
    }
    
    // Clear managed chains set since we've attempted to delete all chains
    managed_chains_.clear();
    
    if (debug_mode_) {
        std::cout << "DEBUG: Chain cleanup " << (success ? "completed successfully" : "completed with errors") << std::endl;
    }
    
    return success;
}

void ChainManager::buildDependencyGraph(const Config& config, 
                                       std::map<std::string, std::set<std::string>>& graph) {
    // Build mapping from section names to actual chain names
    std::map<std::string, std::string> section_to_chain_map;
    
    // Initialize graph with all defined chains from chain_definitions
    for (const auto& [section_name, chain_config] : config.chain_definitions) {
        for (const auto& chain_rule : chain_config.chain) {
            graph[chain_rule.name] = std::set<std::string>();
            section_to_chain_map[section_name] = chain_rule.name;  // Map section name to chain name
        }
    }
    
    // Add dependencies - check chain references within each chain's rules
    for (const auto& [section_name, chain_config] : config.chain_definitions) {
        for (const auto& chain_rule : chain_config.chain) {
            // Check for chain references within this chain's rules
            std::set<std::string> dependencies;
            for (const auto& [rule_name, rule_config] : chain_rule.rules) {
                extractChainReferences(rule_config, dependencies);
            }
            
            // Map section names to actual chain names in dependencies
            std::set<std::string> mapped_dependencies;
            for (const std::string& dep : dependencies) {
                // Check if this is a section name that maps to a chain
                auto it = section_to_chain_map.find(dep);
                if (it != section_to_chain_map.end()) {
                    mapped_dependencies.insert(it->second);  // Use actual chain name
                } else {
                    mapped_dependencies.insert(dep);  // Use as-is (might be direct chain name)
                }
            }
            
            graph[chain_rule.name] = mapped_dependencies;
        }
    }
}

bool ChainManager::hasCycle(const std::map<std::string, std::set<std::string>>& graph) {
    std::set<std::string> visited;
    std::set<std::string> rec_stack;
    
    std::function<bool(const std::string&)> dfs = [&](const std::string& node) -> bool {
        visited.insert(node);
        rec_stack.insert(node);
        
        auto it = graph.find(node);
        if (it != graph.end()) {
            for (const std::string& neighbor : it->second) {
                if (rec_stack.count(neighbor) > 0) {
                    return true; // Back edge found, cycle detected
                }
                if (visited.count(neighbor) == 0 && dfs(neighbor)) {
                    return true;
                }
            }
        }
        
        rec_stack.erase(node);
        return false;
    };
    
    for (const auto& [node, _] : graph) {
        if (visited.count(node) == 0) {
            if (dfs(node)) {
                return true;
            }
        }
    }
    
    return false;
}

std::vector<std::string> ChainManager::topologicalSort(const std::map<std::string, std::set<std::string>>& graph) {
    std::vector<std::string> result;
    std::map<std::string, int> in_degree;
    
    // Calculate in-degrees
    for (const auto& [node, _] : graph) {
        in_degree[node] = 0;
    }
    
    for (const auto& [node, neighbors] : graph) {
        for (const std::string& neighbor : neighbors) {
            in_degree[neighbor]++;
        }
    }
    
    // Use queue for nodes with in-degree 0
    std::queue<std::string> queue;
    for (const auto& [node, degree] : in_degree) {
        if (degree == 0) {
            queue.push(node);
        }
    }
    
    // Process nodes
    while (!queue.empty()) {
        std::string current = queue.front();
        queue.pop();
        result.push_back(current);
        
        auto it = graph.find(current);
        if (it != graph.end()) {
            for (const std::string& neighbor : it->second) {
                in_degree[neighbor]--;
                if (in_degree[neighbor] == 0) {
                    queue.push(neighbor);
                }
            }
        }
    }
    
    return result;
}

void ChainManager::extractChainReferences(const SectionConfig& section_config, 
                                         std::set<std::string>& references) {
    // Check interface_config for chain references
    if (section_config.interface_config && section_config.interface_config->hasChain()) {
        references.insert(*section_config.interface_config->chain);
    }
    
    // Check port configs for chain references
    if (section_config.ports) {
        for (const auto& port_config : *section_config.ports) {
            if (port_config.interface && port_config.interface->hasChain()) {
                references.insert(*port_config.interface->chain);
            }
        }
    }
    
    // Check mac configs for chain references
    if (section_config.mac) {
        for (const auto& mac_config : *section_config.mac) {
            if (mac_config.interface && mac_config.interface->hasChain()) {
                references.insert(*mac_config.interface->chain);
            }
        }
    }
    
    // Recursively check chain rules
    if (section_config.chain_config) {
        for (const auto& chain_rule : section_config.chain_config->chain) {
            for (const auto& [rule_name, rule_config] : chain_rule.rules) {
                extractChainReferences(rule_config, references);
            }
        }
    }
}

} // namespace iptables 