#pragma once

#include "config.hpp"
#include "command_executor.hpp"
#include <string>
#include <vector>
#include <set>
#include <map>

namespace iptables {

/**
 * @brief Manages custom iptables chains for multichain support
 * 
 * The ChainManager handles creation, deletion, and validation of custom iptables chains.
 * It provides dependency resolution to ensure chains are created in the correct order
 * and handles cleanup when chains are no longer needed.
 */
class ChainManager {
public:
    /**
     * @brief Construct a new Chain Manager object
     * 
     * @param executor Reference to command executor for running iptables commands
     * @param debug_mode Whether to run in debug mode (no actual commands executed)
     */
    explicit ChainManager(CommandExecutor& executor, bool debug_mode = false);

    /**
     * @brief Create a custom iptables chain
     * 
     * @param chain_name Name of the chain to create
     * @return true if chain was created successfully or already exists
     * @return false if creation failed
     */
    bool createChain(const std::string& chain_name);

    /**
     * @brief Delete a custom iptables chain
     * 
     * @param chain_name Name of the chain to delete
     * @return true if chain was deleted successfully or doesn't exist
     * @return false if deletion failed
     */
    bool deleteChain(const std::string& chain_name);

    /**
     * @brief Flush all rules from a custom chain
     * 
     * @param chain_name Name of the chain to flush
     * @return true if chain was flushed successfully
     * @return false if flush failed
     */
    bool flushChain(const std::string& chain_name);

    /**
     * @brief Check if a custom chain exists
     * 
     * @param chain_name Name of the chain to check
     * @return true if chain exists
     * @return false if chain doesn't exist or check failed
     */
    bool chainExists(const std::string& chain_name);

    /**
     * @brief Get list of all custom chains
     * 
     * @return std::vector<std::string> List of custom chain names
     */
    std::vector<std::string> listChains();

    /**
     * @brief Process chain configurations from config
     * 
     * Creates all chains defined in the configuration in the correct dependency order.
     * 
     * @param config Configuration containing chain definitions
     * @return true if all chains were processed successfully
     * @return false if any chain processing failed
     */
    bool processChainConfigurations(const Config& config);

    /**
     * @brief Resolve chain dependencies and get creation order
     * 
     * Analyzes chain definitions to determine the correct order for chain creation
     * to satisfy dependencies and detect circular references.
     * 
     * @param config Configuration containing chain definitions
     * @return std::vector<std::string> Ordered list of chain names for creation
     */
    std::vector<std::string> getChainCreationOrder(const Config& config);

    /**
     * @brief Validate chain references in configuration
     * 
     * Ensures all referenced chains are defined and detects circular dependencies.
     * 
     * @param config Configuration to validate
     * @return true if all chain references are valid
     * @return false if validation failed
     */
    bool validateChainReferences(const Config& config);

    /**
     * @brief Cleanup all managed chains
     * 
     * Removes all chains that were created by this manager.
     * Used during reset operations.
     * 
     * @return true if cleanup was successful
     * @return false if cleanup failed
     */
    bool cleanupChains();

    /**
     * @brief Get error message from last operation
     * 
     * @return std::string Error message, empty if no error
     */
    std::string getLastError() const { return last_error_; }

private:
    CommandExecutor& executor_;
    bool debug_mode_;
    std::string last_error_;
    std::set<std::string> managed_chains_;  // Chains created by this manager

    /**
     * @brief Build dependency graph for chains
     * 
     * @param config Configuration containing chain definitions
     * @param graph Output dependency graph (chain -> dependencies)
     */
    void buildDependencyGraph(const Config& config, 
                             std::map<std::string, std::set<std::string>>& graph);

    /**
     * @brief Detect circular dependencies in chain graph
     * 
     * @param graph Dependency graph to check
     * @return true if circular dependencies detected
     * @return false if no circular dependencies
     */
    bool hasCycle(const std::map<std::string, std::set<std::string>>& graph);

    /**
     * @brief Perform topological sort on dependency graph
     * 
     * @param graph Dependency graph
     * @return std::vector<std::string> Topologically sorted chain names
     */
    std::vector<std::string> topologicalSort(const std::map<std::string, std::set<std::string>>& graph);

    /**
     * @brief Extract chain references from a section config
     * 
     * @param section_config Section to analyze
     * @param references Output set of referenced chain names
     */
    void extractChainReferences(const SectionConfig& section_config, 
                               std::set<std::string>& references);

    /**
     * @brief Set last error message
     * 
     * @param error Error message to set
     */
    void setError(const std::string& error) { last_error_ = error; }

    /**
     * @brief Clear last error message
     */
    void clearError() { last_error_.clear(); }
};

} // namespace iptables 