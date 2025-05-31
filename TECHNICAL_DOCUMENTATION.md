# Technical Documentation: iptables-compose-cpp

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Core Components](#core-components)
3. [Header Files Documentation](#header-files-documentation)
4. [Source Files Documentation](#source-files-documentation)
5. [Execution Flow](#execution-flow)
6. [Data Flow Diagrams](#data-flow-diagrams)
7. [Component Interactions](#component-interactions)

## Architecture Overview

The iptables-compose-cpp project follows a modular, object-oriented architecture with clear separation of concerns. The system processes YAML configurations to generate and manage iptables rules with support for advanced features like multiport rules and custom chains.

### Design Patterns Used

- **Command Pattern**: `CommandExecutor` encapsulates iptables commands
- **Factory Pattern**: Rule creation based on configuration types
- **Strategy Pattern**: Different rule types implement common `Rule` interface
- **Validator Pattern**: `RuleValidator` for configuration validation
- **Manager Pattern**: Separate managers for different responsibilities

### Key Architectural Principles

1. **Separation of Concerns**: Each class has a single, well-defined responsibility
2. **Dependency Injection**: Components receive dependencies through constructors
3. **Immutable Operations**: Configuration objects are read-only after creation
4. **Error Handling**: Comprehensive error handling with detailed messages
5. **Testability**: Components are designed for easy unit testing

## Core Components

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                        │
├─────────────────────────────────────────────────────────────┤
│  main.cpp          │  cli_parser.hpp/cpp                    │
│  Application Entry │  Command Line Interface                │
├─────────────────────────────────────────────────────────────┤
│                   Management Layer                          │
├─────────────────────────────────────────────────────────────┤
│  iptables_manager.hpp/cpp  │  chain_manager.hpp/cpp         │
│  Main Orchestration        │  Custom Chain Management       │
│                           │                                │
│  rule_manager.hpp/cpp     │  rule_validator.hpp/cpp        │
│  Rule Collection Mgmt     │  Configuration Validation      │
├─────────────────────────────────────────────────────────────┤
│                   Configuration Layer                       │
├─────────────────────────────────────────────────────────────┤
│  config.hpp/cpp           │  config_parser.hpp/cpp         │
│  Data Structures          │  YAML Processing               │
├─────────────────────────────────────────────────────────────┤
│                     Rule Layer                              │
├─────────────────────────────────────────────────────────────┤
│  rule.hpp/cpp      │  tcp_rule.hpp/cpp   │  udp_rule.hpp/cpp│
│  Base Rule Class   │  TCP Rules          │  UDP Rules       │
│                   │                     │                  │
│  mac_rule.hpp/cpp │  chain_rule.hpp/cpp │                  │
│  MAC Rules        │  Chain Rules        │                  │
├─────────────────────────────────────────────────────────────┤
│                   Execution Layer                           │
├─────────────────────────────────────────────────────────────┤
│  command_executor.hpp/cpp  │  system_utils.hpp/cpp          │
│  Command Execution         │  System Utilities              │
└─────────────────────────────────────────────────────────────┘
```

# Header Files Documentation

## 1. include/main.cpp (Entry Point)

**Purpose**: Application entry point and main execution flow coordinator.

**Key Responsibilities**:
- Command line argument processing
- System requirements validation
- Configuration loading and processing
- Error handling and user feedback

**Execution Logic**:
```cpp
// main() execution flow:
1. Parse CLI arguments using CLIParser
2. Validate system requirements (root, iptables)
3. Handle special operations (--license, --remove-rules)
4. Load and validate configuration file
5. Process configuration through IptablesManager
6. Report success/failure to user
```

## 2. include/cli_parser.hpp

**Purpose**: Command line argument parsing and validation.

### CLIParser Class

```cpp
class CLIParser {
public:
    struct Options {
        std::optional<std::filesystem::path> config_file;
        bool reset = false;
        bool remove_rules = false;
        bool show_license = false;
        bool debug = false;
    };
    
    static Options parse(int argc, char* argv[]);
    static void printUsage();
    static void printLicense();
};
```

**Key Methods**:
- `parse()`: Uses getopt_long for argument processing
- `printUsage()`: Displays help information
- `printLicense()`: Shows MIT license text

**Execution Logic**:
- Processes arguments in order of precedence
- Validates argument combinations
- Provides helpful error messages for invalid options

## 3. include/config.hpp

**Purpose**: Configuration data structures and YAML serialization.

### Core Data Structures

#### PortConfig
```cpp
struct PortConfig {
    std::optional<uint16_t> port;                    // Single port
    std::optional<std::vector<std::string>> range;   // Port ranges
    Protocol protocol = Protocol::Tcp;
    Direction direction = Direction::Input;
    std::vector<std::string> subnets;
    std::optional<uint16_t> forward_port;
    bool allow = true;
    InterfaceConfig interface;
    std::optional<std::string> mac_source;
    std::optional<std::string> target_chain;        // For chain calls
    
    bool isValid() const;
};
```

**Validation Logic**:
- Ensures mutual exclusivity between `port` and `range`
- Validates port range format ("start-end")
- Checks port number bounds (1-65535)
- Validates range logic (start < end)

#### ChainRuleConfig
```cpp
struct ChainRuleConfig {
    std::string name;                                    // Chain name
    Action action = Action::Accept;                      // Default action
    std::map<std::string, SectionConfig> rules;         // Rule groups
    
    bool isValid() const;
};
```

**Chain Management**:
- Defines custom iptables chains
- Contains nested rule configurations
- Supports hierarchical chain structures

### YAML Serialization
- Template specializations for yaml-cpp
- Automatic conversion between YAML and C++ objects
- Error handling for malformed YAML

## 4. include/config_parser.hpp

**Purpose**: YAML configuration file parsing and validation.

### ConfigParser Class

```cpp
class ConfigParser {
public:
    static std::optional<Config> parseFromFile(const std::string& filename);
    static std::optional<Config> parseFromString(const std::string& yaml_content);
    
private:
    static Config parseYamlNode(const YAML::Node& root);
    static FilterConfig parseFilterSection(const YAML::Node& node);
    static SectionConfig parseSection(const YAML::Node& node);
};
```

**Parsing Logic**:
1. Load YAML file using yaml-cpp
2. Validate YAML structure
3. Parse filter section (policies)
4. Parse custom sections with rule definitions
5. Extract chain definitions
6. Validate cross-references

## 5. include/rule.hpp

**Purpose**: Base class for all iptables rules with common interface.

### Rule Class Hierarchy

```cpp
class Rule {
protected:
    Direction direction_;
    Action action_;
    std::vector<std::string> subnets_;
    InterfaceConfig interface_;
    std::optional<std::string> target_chain_;
    
public:
    virtual ~Rule() = default;
    virtual std::string buildIptablesCommand() const = 0;
    virtual std::string getComment() const = 0;
    virtual bool matches(const Rule& other) const = 0;
    
    // Common functionality
    std::string getTargetString() const;
    void addTargetArgs(std::vector<std::string>& args) const;
    void addInterfaceArgs(std::vector<std::string>& args) const;
    void addSubnetArgs(std::vector<std::string>& args) const;
};
```

**Design Pattern**: Template Method Pattern
- Base class defines common structure
- Derived classes implement specific behavior
- Common functionality is reused across rule types

## 6. include/tcp_rule.hpp & include/udp_rule.hpp

**Purpose**: TCP and UDP specific rule implementations with multiport support.

### TcpRule & UdpRule Classes

```cpp
class TcpRule : public Rule {
private:
    std::optional<uint16_t> port_;
    std::vector<std::string> port_ranges_;
    std::optional<uint16_t> forward_port_;
    std::string section_name_;
    std::optional<std::string> mac_source_;
    
public:
    std::string buildIptablesCommand() const override;
    std::string getComment() const override;
    bool matches(const Rule& other) const override;
    
private:
    std::string buildPortForwardingCommand() const;
    std::string buildMultiportCommand() const;
    std::string buildSinglePortCommand() const;
};
```

**Multiport Logic**:
- Detects when multiple port ranges are specified
- Uses `-m multiport --dports` for efficiency
- Converts "start-end" format to "start:end" for iptables
- Falls back to single port syntax when appropriate

**Port Forwarding Logic**:
- Uses NAT table PREROUTING chain
- Generates REDIRECT target with --to-port
- Only supports single ports (iptables limitation)

## 7. include/mac_rule.hpp

**Purpose**: MAC address filtering rule implementation.

### MacRule Class

```cpp
class MacRule : public Rule {
private:
    std::string mac_source_;
    std::string section_name_;
    
public:
    std::string buildIptablesCommand() const override;
    std::string getComment() const override;
    bool matches(const Rule& other) const override;
};
```

**MAC Rule Constraints**:
- Only supports INPUT direction (iptables limitation)
- Uses `-m mac --mac-source` module
- Validates MAC address format during construction

## 8. include/chain_rule.hpp

**Purpose**: Chain call rule implementation for custom chains.

### ChainRule Class

```cpp
class ChainRule : public Rule {
private:
    std::string chain_name_;
    std::string section_name_;
    
public:
    std::string buildIptablesCommand() const override;
    std::string getComment() const override;
    bool matches(const Rule& other) const override;
};
```

**Chain Call Logic**:
- Generates `-j CUSTOM_CHAIN` commands
- Supports all standard rule options (interfaces, subnets)
- Creates proper YAML signatures for chain calls

## 9. include/chain_manager.hpp

**Purpose**: Custom iptables chain management with dependency resolution.

### ChainManager Class

```cpp
class ChainManager {
public:
    bool createChain(const std::string& chain_name, const std::string& table = "filter");
    bool deleteChain(const std::string& chain_name, const std::string& table = "filter");
    bool flushChain(const std::string& chain_name, const std::string& table = "filter");
    bool chainExists(const std::string& chain_name, const std::string& table = "filter");
    
    std::vector<std::string> listChains(const std::string& table = "filter");
    bool processChainConfig(const Config& config);
    bool cleanupChains();
    
private:
    std::vector<std::string> getChainCreationOrder(const Config& config);
    bool hasCircularDependencies(const Config& config);
    void buildDependencyGraph(const Config& config, 
                             std::map<std::string, std::set<std::string>>& graph);
};
```

**Dependency Resolution Algorithm**:
1. Parse all chain definitions and references
2. Build dependency graph
3. Detect circular dependencies using DFS
4. Generate creation order using topological sort
5. Create chains in proper order

**Chain Management Logic**:
- Creates chains before adding rules
- Validates chain existence before operations
- Handles cleanup in reverse dependency order
- Provides comprehensive error reporting

## 10. include/rule_manager.hpp

**Purpose**: Collection management for iptables rules.

### RuleManager Class

```cpp
class RuleManager {
private:
    std::vector<std::unique_ptr<Rule>> rules_;
    CommandExecutor executor_;
    
public:
    void addRule(std::unique_ptr<Rule> rule);
    bool removeRule(const Rule& rule);
    void clearRules();
    
    bool applyRules();
    bool removeAllRules();
    bool removeAllYamlRules();
    
    std::vector<uint32_t> getRuleLineNumbers(const std::string& chain, 
                                           const std::string& comment,
                                           const std::string& table = "filter");
};
```

**Rule Application Logic**:
1. Remove existing rules with matching signatures
2. Generate iptables commands for new rules
3. Execute commands through CommandExecutor
4. Validate successful application
5. Rollback on failure (if possible)

**Signature-based Management**:
- Uses YAML comment signatures for rule identification
- Supports selective rule removal
- Maintains rule ordering during operations

## 11. include/rule_validator.hpp

**Purpose**: Configuration validation and conflict detection.

### RuleValidator Class

```cpp
class RuleValidator {
public:
    static std::vector<ValidationWarning> validateConfiguration(const Config& config);
    static std::vector<ValidationWarning> analyzeRuleOrder(const Config& config);
    static bool hasCircularChainDependencies(const Config& config);
    
private:
    struct RuleSelectivity {
        int subnet_specificity;
        int port_specificity;
        int interface_specificity;
        int mac_specificity;
        bool has_protocol;
        
        int calculateScore() const;
        bool isMoreSpecific(const RuleSelectivity& other) const;
    };
    
    static RuleSelectivity analyzeRule(const PortConfig& port);
    static bool rulesConflict(const PortConfig& rule1, const PortConfig& rule2);
};
```

**Validation Algorithm**:
1. **Rule Order Analysis**: Detects unreachable rules
2. **Conflict Detection**: Identifies conflicting configurations
3. **Specificity Scoring**: Quantifies rule selectivity
4. **Chain Validation**: Ensures valid chain references

**Selectivity Analysis**:
- Subnet specificity: /32 > /24 > /16 > no restriction
- Port specificity: single port > port range > no restriction
- Interface specificity: specific interface > any interface
- Protocol specificity: TCP/UDP > any protocol

## 12. include/iptables_manager.hpp

**Purpose**: Main orchestration class for iptables operations.

### IptablesManager Class

```cpp
class IptablesManager {
private:
    RuleManager rule_manager_;
    ChainManager chain_manager_;
    CommandExecutor executor_;
    
public:
    bool loadConfig(const std::filesystem::path& config_file);
    bool processConfiguration(const Config& config);
    bool resetRules();
    bool removeYamlRules();
    
private:
    bool processFilterConfig(const FilterConfig& filter);
    bool processChainConfigurations(const Config& config);
    bool processSectionConfig(const std::string& section_name, 
                             const SectionConfig& section);
    bool processPortConfig(const PortConfig& port, const std::string& section);
    bool processMacConfig(const MacConfig& mac, const std::string& section);
};
```

**Processing Workflow**:
1. **Chain Creation**: Process chain definitions first
2. **Filter Policies**: Set default chain policies
3. **Section Processing**: Handle custom sections in order
4. **Rule Generation**: Create appropriate rule objects
5. **Application**: Apply rules through RuleManager

## 13. include/command_executor.hpp

**Purpose**: Iptables command execution with comprehensive logging.

### CommandExecutor Class

```cpp
class CommandExecutor {
public:
    struct CommandResult {
        bool success;
        std::string stdout_output;
        std::string stderr_output;
        int exit_code;
        std::string command_line;
        
        bool isSuccess() const { return success && exit_code == 0; }
    };
    
    static CommandResult execute(const std::vector<std::string>& command);
    static CommandResult executeIptables(const std::vector<std::string>& args, 
                                        const std::string& table = "filter");
    
    // Specialized iptables operations
    static CommandResult listRules(const std::string& chain = "INPUT", 
                                 const std::string& table = "filter");
    static CommandResult removeRuleByLineNumber(const std::string& chain, 
                                               int line_number,
                                               const std::string& table = "filter");
    static CommandResult setChainPolicy(const std::string& chain, 
                                       const std::string& policy,
                                       const std::string& table = "filter");
    static CommandResult flushChain(const std::string& chain, 
                                   const std::string& table = "filter");
};
```

**Execution Logic**:
- Command building with argument escaping
- Process execution with output capture
- Comprehensive error reporting
- Logging with multiple levels (Error, Warning, Info, Debug)

## 14. include/system_utils.hpp

**Purpose**: System-level utilities and validation.

### SystemUtils Class

```cpp
class SystemUtils {
public:
    static bool isRoot();
    static bool isIptablesAvailable();
    static bool validateSystemRequirements();
    static CommandResult executeCommand(const std::string& command);
    
private:
    static bool fileExists(const std::string& path);
    static std::string getIptablesVersion();
};
```

**System Validation**:
- Root privilege checking using getuid()
- Iptables availability verification
- System requirements validation
- Cross-platform compatibility considerations

# Source Files Documentation

## 1. src/main.cpp

**Execution Flow**:

```cpp
int main(int argc, char* argv[]) {
    try {
        // 1. Parse command line arguments
        auto options = CLIParser::parse(argc, argv);
        
        // 2. Handle special operations first
        if (options.show_license) {
            CLIParser::printLicense();
            return 0;
        }
        
        // 3. Validate system requirements
        if (!SystemUtils::validateSystemRequirements()) {
            std::cerr << "System validation failed" << std::endl;
            return 1;
        }
        
        // 4. Handle rule removal without configuration
        if (options.remove_rules) {
            IptablesManager manager;
            return manager.removeYamlRules() ? 0 : 1;
        }
        
        // 5. Process configuration file
        if (options.config_file) {
            IptablesManager manager;
            
            // Optional: Reset rules first
            if (options.reset && !manager.resetRules()) {
                std::cerr << "Failed to reset rules" << std::endl;
                return 1;
            }
            
            // Load and apply configuration
            if (options.debug) {
                // Debug mode: validate only
                return validateConfigurationOnly(*options.config_file);
            } else {
                // Normal mode: apply configuration
                return manager.loadConfig(*options.config_file) ? 0 : 1;
            }
        }
        
        // 6. No valid operation specified
        CLIParser::printUsage();
        return 1;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
```

**Error Handling Strategy**:
- Comprehensive exception handling
- Detailed error messages for users
- Proper exit codes for scripting
- Fallback to usage information

## 2. src/config.cpp

**Key Implementation Details**:

### YAML Serialization Templates

```cpp
namespace YAML {
    template<>
    struct convert<PortConfig> {
        static bool decode(const Node& node, PortConfig& config) {
            // 1. Parse port OR range (mutually exclusive)
            if (node["port"]) {
                config.port = node["port"].as<uint16_t>();
            }
            if (node["range"]) {
                config.range = node["range"].as<std::vector<std::string>>();
            }
            
            // 2. Validate mutual exclusivity
            if (config.port && config.range) {
                throw YAML::Exception(node.Mark(), 
                    "Cannot specify both 'port' and 'range'");
            }
            
            // 3. Parse other fields with defaults
            config.protocol = parseProtocol(node["protocol"]);
            config.direction = parseDirection(node["direction"]);
            config.allow = node["allow"].as<bool>(true);
            
            // 4. Validate configuration
            if (!config.isValid()) {
                throw YAML::Exception(node.Mark(), "Invalid port configuration");
            }
            
            return true;
        }
    };
}
```

### Validation Logic

```cpp
bool PortConfig::isValid() const {
    // 1. Must have either port or range
    if (!port && !range) {
        return false;
    }
    
    // 2. Cannot have both port and range
    if (port && range) {
        return false;
    }
    
    // 3. Validate port range format
    if (range) {
        for (const auto& range_str : *range) {
            if (!isValidPortRange(range_str)) {
                return false;
            }
        }
    }
    
    // 4. Port forwarding restrictions
    if (forward_port && range) {
        return false; // Forwarding not supported with ranges
    }
    
    return true;
}

bool PortConfig::isValidPortRange(const std::string& range_str) const {
    auto pos = range_str.find('-');
    if (pos == std::string::npos) {
        return false;
    }
    
    try {
        int start = std::stoi(range_str.substr(0, pos));
        int end = std::stoi(range_str.substr(pos + 1));
        
        return (start >= 1 && start <= 65535 && 
                end >= 1 && end <= 65535 && 
                start < end);
    } catch (...) {
        return false;
    }
}
```

## 3. src/iptables_manager.cpp

**Core Processing Logic**:

### Configuration Processing Workflow

```cpp
bool IptablesManager::processConfiguration(const Config& config) {
    try {
        // 1. Process chain definitions first (dependency order)
        if (!processChainConfigurations(config)) {
            std::cerr << "Failed to process chain configurations" << std::endl;
            return false;
        }
        
        // 2. Process filter section (policies)
        if (config.filter) {
            if (!processFilterConfig(*config.filter)) {
                std::cerr << "Failed to process filter configuration" << std::endl;
                return false;
            }
        }
        
        // 3. Process custom sections in order
        for (const auto& [section_name, section_config] : config.custom_sections) {
            if (!processSectionConfig(section_name, section_config)) {
                std::cerr << "Failed to process section: " << section_name << std::endl;
                return false;
            }
        }
        
        // 4. Apply all generated rules
        if (!rule_manager_.applyRules()) {
            std::cerr << "Failed to apply rules" << std::endl;
            return false;
        }
        
        std::cout << "Configuration processed successfully" << std::endl;
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "Error processing configuration: " << e.what() << std::endl;
        return false;
    }
}
```

### Rule Generation Strategy

```cpp
bool IptablesManager::processPortConfig(const PortConfig& port, 
                                       const std::string& section) {
    try {
        std::unique_ptr<Rule> rule;
        
        // 1. Determine rule type based on protocol
        if (port.protocol == Protocol::Tcp) {
            rule = std::make_unique<TcpRule>(port, section);
        } else if (port.protocol == Protocol::Udp) {
            rule = std::make_unique<UdpRule>(port, section);
        } else {
            std::cerr << "Unsupported protocol" << std::endl;
            return false;
        }
        
        // 2. Remove existing rules with same signature
        std::string comment = rule->getComment();
        std::string chain = directionToChain(port.direction);
        
        auto line_numbers = rule_manager_.getRuleLineNumbers(chain, comment);
        for (auto it = line_numbers.rbegin(); it != line_numbers.rend(); ++it) {
            executor_.removeRuleByLineNumber(chain, *it);
        }
        
        // 3. Add new rule to rule manager
        rule_manager_.addRule(std::move(rule));
        
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "Error processing port config: " << e.what() << std::endl;
        return false;
    }
}
```

## 4. src/chain_manager.cpp

**Chain Management Implementation**:

### Dependency Resolution Algorithm

```cpp
std::vector<std::string> ChainManager::getChainCreationOrder(const Config& config) {
    // 1. Build dependency graph
    std::map<std::string, std::set<std::string>> graph;
    buildDependencyGraph(config, graph);
    
    // 2. Check for circular dependencies
    if (hasCircularDependencies(graph)) {
        throw std::runtime_error("Circular chain dependencies detected");
    }
    
    // 3. Topological sort for creation order
    std::vector<std::string> order;
    std::set<std::string> visited;
    std::set<std::string> temp_visited;
    
    std::function<void(const std::string&)> visit = [&](const std::string& chain) {
        if (temp_visited.count(chain)) {
            throw std::runtime_error("Circular dependency detected: " + chain);
        }
        if (!visited.count(chain)) {
            temp_visited.insert(chain);
            
            if (graph.count(chain)) {
                for (const auto& dependency : graph[chain]) {
                    visit(dependency);
                }
            }
            
            temp_visited.erase(chain);
            visited.insert(chain);
            order.push_back(chain);
        }
    };
    
    // Visit all chains
    for (const auto& [chain, _] : graph) {
        visit(chain);
    }
    
    return order;
}
```

### Chain Creation Process

```cpp
bool ChainManager::processChainConfig(const Config& config) {
    try {
        // 1. Get creation order (handles dependencies)
        auto creation_order = getChainCreationOrder(config);
        
        // 2. Create chains in dependency order
        for (const auto& chain_name : creation_order) {
            if (!createChain(chain_name)) {
                std::cerr << "Failed to create chain: " << chain_name << std::endl;
                return false;
            }
        }
        
        // 3. Process rules within each chain
        for (const auto& [section_name, section_config] : config.custom_sections) {
            if (section_config.chain_config) {
                for (const auto& chain_rule : section_config.chain_config->chain) {
                    if (!processChainRules(chain_rule)) {
                        std::cerr << "Failed to process chain rules: " 
                                  << chain_rule.name << std::endl;
                        return false;
                    }
                }
            }
        }
        
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "Error processing chain configuration: " << e.what() << std::endl;
        return false;
    }
}
```

## 5. src/rule_validator.cpp

**Validation Implementation**:

### Rule Order Analysis

```cpp
std::vector<ValidationWarning> RuleValidator::analyzeRuleOrder(const Config& config) {
    std::vector<ValidationWarning> warnings;
    
    // Analyze each section separately
    for (const auto& [section_name, section_config] : config.custom_sections) {
        // 1. Analyze port rules within section
        for (size_t i = 0; i < section_config.ports.size(); ++i) {
            const auto& rule1 = section_config.ports[i];
            auto selectivity1 = analyzeRule(rule1);
            
            for (size_t j = i + 1; j < section_config.ports.size(); ++j) {
                const auto& rule2 = section_config.ports[j];
                auto selectivity2 = analyzeRule(rule2);
                
                // 2. Check if later rule is unreachable
                if (selectivity1.isMoreSpecific(selectivity2) && 
                    rulesConflict(rule1, rule2)) {
                    
                    ValidationWarning warning;
                    warning.type = ValidationWarning::Type::UnreachableRule;
                    warning.message = createUnreachableRuleMessage(rule1, rule2, 
                                                                 section_name, i, j);
                    warnings.push_back(warning);
                }
                
                // 3. Check for redundant rules
                if (selectivity1.calculateScore() == selectivity2.calculateScore() &&
                    rulesConflict(rule1, rule2)) {
                    
                    ValidationWarning warning;
                    warning.type = ValidationWarning::Type::RedundantRule;
                    warning.message = createRedundantRuleMessage(rule1, rule2, 
                                                               section_name, i, j);
                    warnings.push_back(warning);
                }
            }
        }
    }
    
    return warnings;
}
```

### Selectivity Analysis

```cpp
RuleValidator::RuleSelectivity RuleValidator::analyzeRule(const PortConfig& port) {
    RuleSelectivity selectivity;
    
    // 1. Subnet specificity
    if (port.subnets.empty()) {
        selectivity.subnet_specificity = 0; // Any subnet
    } else {
        int max_specificity = 0;
        for (const auto& subnet : port.subnets) {
            // Parse CIDR notation
            auto pos = subnet.find('/');
            if (pos != std::string::npos) {
                int cidr = std::stoi(subnet.substr(pos + 1));
                max_specificity = std::max(max_specificity, cidr);
            }
        }
        selectivity.subnet_specificity = max_specificity;
    }
    
    // 2. Port specificity
    if (port.port) {
        selectivity.port_specificity = 100; // Single port is most specific
    } else if (port.range) {
        selectivity.port_specificity = 50;  // Range is less specific
    } else {
        selectivity.port_specificity = 0;   // Any port
    }
    
    // 3. Interface specificity
    if (port.interface.input || port.interface.output) {
        selectivity.interface_specificity = 10;
    } else {
        selectivity.interface_specificity = 0;
    }
    
    // 4. MAC specificity
    if (port.mac_source) {
        selectivity.mac_specificity = 10;
    } else {
        selectivity.mac_specificity = 0;
    }
    
    selectivity.has_protocol = true; // Port rules always have protocol
    
    return selectivity;
}
```

## 6. src/tcp_rule.cpp & src/udp_rule.cpp

**Rule Generation Logic**:

### Multiport Command Generation

```cpp
std::string TcpRule::buildIptablesCommand() const {
    std::vector<std::string> args;
    
    // 1. Basic command structure
    args.push_back("iptables");
    args.push_back("-A");
    args.push_back(directionToChain(direction_));
    
    // 2. Protocol specification
    args.push_back("-p");
    args.push_back("tcp");
    
    // 3. Port specification (single or multiport)
    if (port_) {
        // Single port
        args.push_back("-m");
        args.push_back("tcp");
        args.push_back("--dport");
        args.push_back(std::to_string(*port_));
    } else if (!port_ranges_.empty()) {
        // Multiple port ranges - use multiport
        args.push_back("-m");
        args.push_back("multiport");
        args.push_back("--dports");
        
        // Convert ranges to iptables format
        std::vector<std::string> iptables_ranges;
        for (const auto& range : port_ranges_) {
            // Convert "1000-2000" to "1000:2000"
            std::string iptables_range = range;
            std::replace(iptables_range.begin(), iptables_range.end(), '-', ':');
            iptables_ranges.push_back(iptables_range);
        }
        
        args.push_back(join(iptables_ranges, ","));
    }
    
    // 4. Add interface specifications
    addInterfaceArgs(args);
    
    // 5. Add subnet restrictions
    addSubnetArgs(args);
    
    // 6. Add MAC source filtering
    if (mac_source_) {
        args.push_back("-m");
        args.push_back("mac");
        args.push_back("--mac-source");
        args.push_back(*mac_source_);
    }
    
    // 7. Add target (action or chain)
    addTargetArgs(args);
    
    // 8. Add comment for rule identification
    args.push_back("-m");
    args.push_back("comment");
    args.push_back("--comment");
    args.push_back(getComment());
    
    return join(args, " ");
}
```

### Port Forwarding Implementation

```cpp
std::string TcpRule::buildPortForwardingCommand() const {
    if (!forward_port_ || !port_) {
        return "";  // Port forwarding requires single port
    }
    
    std::vector<std::string> args;
    
    // Use NAT table PREROUTING chain
    args.push_back("iptables");
    args.push_back("-t");
    args.push_back("nat");
    args.push_back("-A");
    args.push_back("PREROUTING");
    
    // Protocol and port
    args.push_back("-p");
    args.push_back("tcp");
    args.push_back("--dport");
    args.push_back(std::to_string(*port_));
    
    // Interface (if specified)
    if (interface_.input) {
        args.push_back("-i");
        args.push_back(*interface_.input);
    }
    
    // REDIRECT target with destination port
    args.push_back("-j");
    args.push_back("REDIRECT");
    args.push_back("--to-port");
    args.push_back(std::to_string(*forward_port_));
    
    // Comment for identification
    args.push_back("-m");
    args.push_back("comment");
    args.push_back("--comment");
    args.push_back(getComment());
    
    return join(args, " ");
}
```

## 7. src/command_executor.cpp

**Command Execution Implementation**:

### Process Execution with Output Capture

```cpp
CommandExecutor::CommandResult CommandExecutor::execute(
    const std::vector<std::string>& command) {
    
    CommandResult result;
    result.command_line = join(command, " ");
    
    try {
        // 1. Build command string
        std::string cmd_str = escapeCommand(command);
        
        // 2. Open process with pipes
        FILE* pipe = popen((cmd_str + " 2>&1").c_str(), "r");
        if (!pipe) {
            result.success = false;
            result.stderr_output = "Failed to execute command";
            return result;
        }
        
        // 3. Read output
        char buffer[128];
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            result.stdout_output += buffer;
        }
        
        // 4. Get exit code
        result.exit_code = pclose(pipe);
        result.success = (result.exit_code == 0);
        
        // 5. Log command execution
        if (logging_enabled_) {
            logCommand(command, result);
        }
        
        return result;
        
    } catch (const std::exception& e) {
        result.success = false;
        result.stderr_output = e.what();
        return result;
    }
}
```

### Specialized Iptables Operations

```cpp
CommandExecutor::CommandResult CommandExecutor::removeRuleByLineNumber(
    const std::string& chain, int line_number, const std::string& table) {
    
    std::vector<std::string> args = {
        "iptables",
        "-t", table,
        "-D", chain,
        std::to_string(line_number)
    };
    
    auto result = execute(args);
    
    if (result.isSuccess()) {
        log(LogLevel::Info, "Removed rule from " + chain + 
            " at line " + std::to_string(line_number));
    } else {
        log(LogLevel::Error, "Failed to remove rule: " + result.stderr_output);
    }
    
    return result;
}
```

# Execution Flow

## 1. Application Startup Flow

```
main() 
├── CLIParser::parse()
├── SystemUtils::validateSystemRequirements()
├── Handle special operations (--license, --remove-rules)
└── IptablesManager::loadConfig()
    ├── ConfigParser::parseFromFile()
    ├── RuleValidator::validateConfiguration()
    └── IptablesManager::processConfiguration()
```

## 2. Configuration Processing Flow

```
processConfiguration()
├── processChainConfigurations()
│   ├── ChainManager::getChainCreationOrder()
│   ├── ChainManager::createChain() (for each chain)
│   └── Process chain rules
├── processFilterConfig()
│   ├── Set chain policies (INPUT/OUTPUT/FORWARD)
│   └── Process filter MAC rules
└── processSectionConfig() (for each section)
    ├── processPortConfig() (for each port rule)
    ├── processMacConfig() (for each MAC rule)
    └── processInterfaceConfig() (for chain calls)
```

## 3. Rule Generation Flow

```
processPortConfig()
├── Create Rule object (TcpRule/UdpRule based on protocol)
├── Remove existing rules with same signature
│   ├── Rule::getComment() (generate signature)
│   ├── RuleManager::getRuleLineNumbers()
│   └── CommandExecutor::removeRuleByLineNumber()
└── RuleManager::addRule()
```

## 4. Rule Application Flow

```
RuleManager::applyRules()
├── For each rule:
│   ├── Rule::buildIptablesCommand()
│   ├── CommandExecutor::executeIptables()
│   └── Validate success
└── Handle rollback on failure
```

# Data Flow Diagrams

## 1. Configuration Processing Data Flow

```
YAML File → ConfigParser → Config Object → IptablesManager
                                              ↓
Chain Definitions → ChainManager → iptables chain creation
                                              ↓
Filter Config → Policy Rules → CommandExecutor → iptables policies
                                              ↓
Section Config → Rule Objects → RuleManager → iptables rules
```

## 2. Rule Generation Data Flow

```
PortConfig → Rule Factory → TcpRule/UdpRule
                              ↓
                         buildIptablesCommand()
                              ↓
                         iptables command string
                              ↓
                         CommandExecutor
                              ↓
                         System iptables binary
```

## 3. Chain Management Data Flow

```
Chain Definitions → Dependency Graph → Topological Sort → Creation Order
                                                              ↓
                                                         ChainManager
                                                              ↓
                                                         iptables -N commands
```

# Component Interactions

## 1. Core Component Relationships

- **IptablesManager** orchestrates all operations
- **ChainManager** handles custom chain lifecycle
- **RuleManager** manages rule collections
- **CommandExecutor** provides iptables interface
- **ConfigParser** transforms YAML to objects
- **RuleValidator** ensures configuration validity

## 2. Rule Class Hierarchy Interactions

- **Rule** base class defines common interface
- **TcpRule/UdpRule** implement protocol-specific logic
- **MacRule** handles MAC address filtering
- **ChainRule** manages chain calls

## 3. Error Handling Chain

```
Operation Failure → Component Error Handler → IptablesManager → main() → User
                                                   ↓
                                              Rollback Logic (when possible)
                                                   ↓
                                              Cleanup Operations
```

## 4. Validation Pipeline

```
YAML Input → ConfigParser validation → Config object validation
                                             ↓
                                      RuleValidator analysis
                                             ↓
                                      Warning generation
                                             ↓
                                      User feedback
```

This comprehensive documentation covers all major components, their execution logic, and interactions within the iptables-compose-cpp system. The modular architecture ensures maintainability while providing powerful features for complex iptables management scenarios. 