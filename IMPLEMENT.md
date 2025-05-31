# Implementation Plan: iptables-compose-cpp

This document outlines the implementation plan for porting the Rust-based iptables-compose application to C++. The goal is to maintain feature parity while leveraging the existing C++ class structure.

## Chapter 1: Architecture Overview

### 1.1 Current State Analysis

The existing C++ codebase has a solid foundation with:
- **Rule hierarchy**: Base `Rule` class with specialized implementations (`TcpRule`, `UdpRule`, `MacRule`)
- **Management layer**: `IptablesManager` for high-level operations, `RuleManager` for rule collection management
- **Build system**: CMake with yaml-cpp dependency already configured
- **Multiport support**: Complete implementation of port ranges using iptables multiport extension

### 1.2 Rust Implementation Architecture

The Rust implementation follows a functional approach with these key components:
1. **CLI parsing**: Using `clap` for command-line argument handling
2. **Configuration structures**: Nested structs representing YAML configuration
3. **Rule processing**: Functions that transform configuration into iptables commands
4. **Command execution**: Direct system calls to iptables binary
5. **Rule management**: Signature-based rule identification and removal

### 1.3 Target C++ Architecture

The C++ implementation maintains object-oriented principles with enhanced multiport support:

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Application   │───→│   IptablesManager │───→│   RuleManager   │
│   (main.cpp)    │    │   (w/ multiport)  │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   ConfigParser  │    │  CommandExecutor │    │   Rule classes  │
│  (w/ ranges)    │    │                  │    │  (w/ multiport) │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  RuleValidator  │    │   SystemUtils    │    │ Multiport Rules │
│                 │    │                  │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## Chapter 2: Logic Explanation

### 2.1 Configuration Processing

The implementation processes YAML configurations with enhanced multiport support:

1. **YAML Parsing**: Deserialize YAML into structured data with range support
2. **Filter Policies**: Set default chain policies (INPUT, OUTPUT, FORWARD)
3. **Section Processing**: Handle custom sections with port and MAC rules
4. **Multiport Processing**: Convert port ranges to optimized iptables multiport commands
5. **Rule Generation**: Convert configuration to iptables commands

Key configuration structures:
- `Config`: Root configuration object
- `FilterConfig`: Chain policies and filter-specific MAC rules
- `SectionConfig`: Custom sections with ports and MAC rules
- `PortConfig`: Individual port rule configuration (enhanced with `range` field)
- `MacConfig`: MAC address filtering rules

### 2.2 Multiport Implementation ✨ **NEW**

#### 2.2.1 Configuration Structure Enhancement
The `PortConfig` structure has been enhanced to support both single ports and port ranges:

```cpp
struct PortConfig {
    std::optional<uint16_t> port;                    // Single port (mutually exclusive with range)
    std::optional<std::vector<std::string>> range;   // Port ranges like ["1000-2000", "3000-4000"]
    Protocol protocol = Protocol::Tcp;
    Direction direction = Direction::Input;
    // ... other fields
    
    bool isValid() const;                           // Validates mutual exclusivity and range format
private:
    bool isValidPortRange(const std::string& range_str) const;
};
```

#### 2.2.2 YAML Syntax Support
The implementation supports the exact syntax from the original requirement:

```yaml
# Single port (existing syntax - backward compatible)
ssh:
  ports:
    - port: 22
      allow: true

# Multiple port ranges (new syntax)
vscode:
  ports:
    - range: 
        - "1000-2000"
        - "3000-4000"
      allow: true
```

#### 2.2.3 iptables Command Generation
The multiport implementation generates optimized iptables commands:

- **Single ports**: Use standard iptables syntax (`--dport`)
- **Port ranges**: Use multiport extension (`-m multiport --dports range1,range2,range3`)

Generated commands:
```bash
# Single port
iptables -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT

# Multiple ranges  
iptables -A INPUT -p tcp -m multiport --dports 1000:2000,3000:4000 -j ACCEPT
```

#### 2.2.4 Validation and Error Handling
Comprehensive validation includes:
- **Mutual exclusivity**: Prevents specifying both `port` and `range`
- **Range format validation**: Ensures "start-end" format with proper numbers
- **Port range logic**: Validates start < end and both are valid port numbers (1-65535)
- **iptables limits**: Respects multiport extension limit of 15 port specifications
- **Port forwarding restriction**: Prevents using ranges with forwarding (not supported by iptables)

#### 2.2.5 Rule Order Analysis Enhancement
The rule validation system has been enhanced to understand multiport rules:
- **Port range selectivity analysis**: Analyzes how specific port ranges are compared to single ports
- **Conflict detection**: Identifies potential conflicts between single ports and ranges
- **Optimization suggestions**: Could suggest combining adjacent ranges (future enhancement)

### 2.3 Rule Management Logic

#### 2.3.1 Rule Identification
Rules are identified using comment-based signatures (enhanced for multiport):
```
YAML:section:type:details:interface:mac
```

Examples:
- Single port: `YAML:web:port:80:i:eth0:o:any:mac:any`
- Port ranges: `YAML:vscode:port:1000-2000,3000-4000:i:any:o:any:mac:any`
- MAC rule: `YAML:filter:mac:aa:bb:cc:dd:ee:ff:i:any:o:any`

#### 2.3.2 Rule Removal Strategy
1. List existing rules with line numbers
2. Find rules matching comment patterns (including multiport signatures)
3. Remove rules in reverse order (highest line number first)
4. This prevents line number shifting issues

#### 2.3.3 Rule Application
1. Remove existing rules with same signature
2. Build new iptables command (single port or multiport)
3. Execute command with proper error handling

### 2.4 Command Line Interface

The implementation supports all original commands plus enhanced debug mode:
- `config <file>`: Apply configuration from YAML file
- `--reset`: Reset all iptables rules before applying config
- `--remove-rules`: Remove all rules with YAML comments
- `--debug`: Validate configuration without applying (enhanced with multiport validation)
- `--license`: Display license information

### 2.5 Rule Ordering Design

#### 2.5.1 Importance of Rule Order in iptables
In iptables, rule order is critical because rules are evaluated sequentially from top to bottom within each chain. The first rule that matches a packet determines the action taken. This makes preserving the exact order of rules as they appear in the YAML configuration file essential for correct firewall behavior.

#### 2.5.2 Order Preservation Strategy
The C++ implementation ensures rule order preservation through the following design choices:

1. **Section Order Preservation**:
   - Use `std::vector<std::pair<std::string, SectionConfig>>` instead of `std::map` for `custom_sections`
   - Process sections in the exact order they appear in the YAML file
   - YAML parsing preserves the natural document order through ordered iteration

2. **Rule Order Within Sections**:
   - All rule vectors (`ports`, `mac`, `interface`) maintain their order from YAML
   - Rules are processed sequentially within each section
   - Use `iptables -A` (append) instead of `-I` (insert) to maintain order

3. **Cross-Section Rule Application**:
   - Filter section is always processed first (policies and filter-specific MAC rules)
   - Custom sections are processed in YAML document order
   - Within each section, rules are applied in this order: ports → mac → interface

#### 2.5.3 iptables Command Strategy
- **Remove existing rules**: Before adding new rules, remove rules with matching signatures to prevent duplicates
- **Append rules**: Use `-A` (append) to add rules at the end of chains, preserving order
- **Line number deletion**: When removing rules, use descending line number order to prevent index shifting

**Example YAML Processing Order**:
```yaml
filter:        # 1. Processed first
  input: drop
  mac: [...]

ssh:           # 2. Processed second
  ports: [...]

web:           # 3. Processed third  
  ports: [...]
  mac: [...]
```

This ensures that rules are applied to iptables in the exact sequence they appear in the configuration file.

#### 2.5.4 Safety Considerations for Remote Systems

**Important**: When working on remote systems (VMs, servers accessed via SSH), avoid using `drop` policies in the filter section as they will immediately cut off network access. 

**Safe Examples for Remote Testing**:
```yaml
filter:
  input: accept    # Safe - won't cut SSH connection
  output: accept   # Safe - allows outgoing traffic
  forward: accept  # Safe - allows forwarding
```

**Dangerous Example for Remote Systems**:
```yaml
filter:
  input: drop      # DANGEROUS - will cut SSH connection immediately!
```

The implementation includes safe example configurations that use `accept` policies to prevent accidental lockouts during development and testing.

#### 2.5.5 Rule Order Validation

To help users identify potential configuration issues, the implementation includes an intelligent rule order validator that analyzes the configuration before applying it to iptables.

**Validation Features**:
1. **Unreachable Rule Detection**: Identifies rules that will never be executed because earlier rules with broader conditions overshadow them
2. **Redundant Rule Detection**: Finds rules that have the same effect as earlier rules
3. **Subnet Overlap Analysis**: Detects when subnet specifications create rule conflicts

**Validation Logic**:
The validator analyzes rule selectivity by examining:
- **Subnet specificity**: More specific subnets (e.g., `/32`) vs. broader subnets (e.g., `/24`) or no subnet restriction
- **Port specificity**: Specific ports vs. no port restriction
- **Protocol matching**: TCP vs. UDP rules
- **Interface restrictions**: Specific interfaces vs. any interface
- **MAC address filtering**: Specific MAC addresses vs. no MAC restriction

**Example Problematic Configurations**:
```yaml
# PROBLEM: Second rule will never be reached
web_section:
  ports:
    - port: 80
      protocol: tcp
      subnet: ["192.168.1.0/24"]  # Broader subnet
      allow: false
    - port: 80
      protocol: tcp
      subnet: ["192.168.1.100/32"] # More specific subnet - unreachable!
      allow: true
```

**Validation Output**:
```
Found 1 potential rule ordering issue(s):
  WARNING (Unreachable Rule): Rule will never be executed: port 80 (TCP) from subnets: 192.168.1.100/32 -> ACCEPT in section 'web_section' (rule #2) is overshadowed by port 80 (TCP) from subnets: 192.168.1.0/24 -> DROP in section 'web_section' (rule #1)
```

**Implementation Components**:
- `RuleValidator` class with static validation methods
- `ValidationWarning` struct to represent detected issues
- `RuleSelectivity` struct to analyze rule characteristics
- Integration into the main configuration loading process
- Debug mode (`--debug`) for testing validation without applying rules

The validator helps prevent common iptables configuration mistakes and ensures that rules work as intended by the administrator.

### 2.6 Special Cases Handling

1. **Port Forwarding**: Uses NAT table PREROUTING chain with REDIRECT target
2. **MAC Rules**: Only allowed in INPUT direction
3. **Interface Specifications**: Support for input (-i) and output (-o) interfaces
4. **Subnet Filtering**: Multiple subnets can be specified as comma-separated list

## Chapter 3: Implementation Plan

### 3.1 Phase 1: Core Infrastructure

#### 3.1.1 Command Line Argument Parsing
**Files to create/modify**: `include/cli_parser.hpp`, `src/cli_parser.cpp`

**Requirements**:
- Parse configuration file path
- Handle boolean flags (reset, remove-rules, license)
- Validate argument combinations
- Use standard C++ approach (getopt_long or similar)

**Implementation details**:
```cpp
class CLIParser {
public:
    struct Options {
        std::optional<std::filesystem::path> config_file;
        bool reset = false;
        bool remove_rules = false;
        bool show_license = false;
    };
    
    static Options parse(int argc, char* argv[]);
private:
    static void printUsage();
    static void printLicense();
};
```

#### 3.1.2 Configuration Structures
**Files to create/modify**: `include/config.hpp`, `src/config.cpp`

**Requirements**:
- Mirror Rust configuration structures
- Use yaml-cpp for parsing
- Support optional fields with std::optional
- Provide validation methods

**Key structures**:
```cpp
struct PortConfig {
    uint16_t port;
    Protocol protocol = Protocol::Tcp;
    Direction direction = Direction::Input;
    std::vector<std::string> subnets;
    std::optional<uint16_t> forward_port;
    bool allow = true;
    InterfaceConfig interface;
    std::optional<std::string> mac_source;
};

struct MacConfig {
    std::string mac_source;
    Direction direction = Direction::Input;
    std::vector<std::string> subnets;
    bool allow = true;
    InterfaceConfig interface;
};

struct FilterConfig {
    std::optional<Action> input_policy;
    std::optional<Action> output_policy;
    std::optional<Action> forward_policy;
    std::vector<MacConfig> mac_rules;
};

struct SectionConfig {
    std::vector<PortConfig> ports;
    std::vector<MacConfig> mac_rules;
};

struct Config {
    std::optional<FilterConfig> filter;
    std::map<std::string, SectionConfig> custom_sections;
};
```

#### 3.1.3 Configuration Data Structures
- [x] Create `include/config.hpp` header file
- [x] Define `PortConfig` struct with all required fields
- [x] Define `MacConfig` struct with all required fields
- [x] Define `FilterConfig` struct with all required fields
- [x] Define `SectionConfig` struct with all required fields
- [x] Define `Config` root struct with all required fields
- [x] Add validation methods for each config type
- [x] Add YAML serialization support using yaml-cpp
- [x] Complete YAML template specializations for all config types
- [x] Support for optional fields using std::optional
- [x] Integration with existing rule system enums and types
- [x] **Rule order preservation using ordered containers**

### 3.2 Phase 2: Rule System Enhancement

#### 3.2.1 Enhanced Rule Classes
**Files to modify**: `include/rule.hpp`, rule implementation files

**Requirements**:
- Add comment generation methods matching Rust patterns
- Support port forwarding (NAT rules)
- Enhanced MAC rule support
- Interface configuration support

**New rule types**:
```cpp
class PortForwardRule : public Rule {
private:
    uint16_t source_port_;
    uint16_t target_port_;
    Protocol protocol_;
    std::string section_name_;
    std::optional<std::string> mac_source_;
};

class PolicyRule : public Rule {
private:
    std::string chain_;
    Action policy_;
};
```

#### 3.2.2 Command Executor
**Files to create**: `include/command_executor.hpp`, `src/command_executor.cpp`

**Requirements**:
- Execute iptables commands with error handling
- Capture output for rule listing
- Support different iptables tables (filter, nat, mangle)
- Logging and error reporting

```cpp
class CommandExecutor {
public:
    struct CommandResult {
        bool success;
        std::string stdout_output;
        std::string stderr_output;
    };
    
    static CommandResult execute(const std::vector<std::string>& args);
    static CommandResult executeIptables(const std::vector<std::string>& args);
    static void enableLogging(bool enable);
};
```

### 3.3 Phase 3: Rule Management

#### 3.3.1 Enhanced RuleManager
**Files to modify**: `include/rule_manager.hpp`, `src/rule_manager.cpp`

**Requirements**:
- Rule signature matching (comment-based)
- Rule removal by signature
- Line number based deletion
- Support for multiple iptables tables

**New methods**:
```cpp
class RuleManager {
public:
    // Existing methods...
    
    // New methods for Rust feature parity
    std::vector<uint32_t> getRuleLineNumbers(const std::string& chain, 
                                           const std::string& comment,
                                           const std::string& table = "filter");
    bool removeRulesBySignature(const std::string& chain, 
                               const std::string& comment,
                               const std::string& table = "filter");
    bool removeAllYamlRules();
    bool resetAllPolicies();
    
private:
    CommandExecutor executor_;
};
```

#### 3.3.2 Enhanced IptablesManager
**Files to modify**: `include/iptables_manager.hpp`, `src/iptables_manager.cpp`

**Requirements**:
- Process complete Config structures
- Handle filter policies
- Support custom sections
- Port forwarding rules
- Rule replacement logic

**New methods**:
```cpp
class IptablesManager {
public:
    // Existing methods...
    
    // New methods for Rust feature parity
    bool processConfig(const Config& config);
    bool processFilterConfig(const FilterConfig& filter);
    bool processPortConfig(const PortConfig& port, const std::string& section);
    bool processMacConfig(const MacConfig& mac, const std::string& section);
    bool removeAllYamlRules();
    
private:
    ConfigParser config_parser_;
    CommandExecutor executor_;
    // Existing members...
};
```

### 3.4 Phase 4: Main Application Logic

#### 3.4.1 Enhanced main.cpp
**Files to modify**: `src/main.cpp`

**Requirements**:
- Integrate CLI parsing
- Handle all command-line options
- Proper error handling and logging
- Match Rust application behavior

**Implementation structure**:
```cpp
int main(int argc, char* argv[]) {
    try {
        auto options = CLIParser::parse(argc, argv);
        
        if (options.show_license) {
            CLIParser::printLicense();
            return 0;
        }
        
        if (options.remove_rules) {
            IptablesManager manager;
            return manager.removeAllYamlRules() ? 0 : 1;
        }
        
        if (options.config_file) {
            IptablesManager manager;
            
            if (options.reset) {
                manager.resetRules();
            }
            
            return manager.loadConfig(*options.config_file) ? 0 : 1;
        }
        
        CLIParser::printUsage();
        return 1;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
```

### 3.5 Phase 5: Testing and Validation

#### 3.5.1 Unit Tests
**Files to create**: `tests/` directory structure

**Requirements**:
- Test configuration parsing
- Test rule generation
- Test command execution (with mocking)
- Test rule management operations

#### 3.5.2 Integration Tests
**Requirements**:
- Test with sample YAML configurations
- Validate iptables command generation
- Test rule removal and replacement
- Verify port forwarding rules

#### 3.5.3 Compatibility Testing
**Requirements**:
- Compare outputs with Rust implementation
- Test with complex configurations
- Validate error handling
- Performance comparison

### 3.6 Implementation Priority

1. **High Priority** (Core functionality):
   - CLI argument parsing
   - Configuration structures and parsing
   - **Rule order preservation** (sections and within sections)
   - Basic rule processing
   - Command execution

2. **Medium Priority** (Advanced features):
   - Port forwarding rules
   - MAC rule processing
   - Rule signature matching and removal
   - Policy management

3. **Low Priority** (Polish and optimization):
   - Enhanced error messages
   - Logging improvements
   - Performance optimizations
   - Extended testing

### 3.7 Dependencies and Requirements

#### 3.7.1 External Dependencies
- **yaml-cpp**: Already configured in CMakeLists.txt
- **Standard C++17**: Already specified in build configuration

#### 3.7.2 System Requirements
- **iptables**: Must be available in system PATH
- **Root privileges**: Required for iptables operations
- **Linux system**: iptables is Linux-specific

#### 3.7.3 Build System Updates
No major changes required to CMakeLists.txt, but may need:
- Additional source files as they are created
- Potential test framework integration
- Documentation generation tools

### 3.8 Migration Strategy

1. **Incremental implementation**: Implement features in phases
2. **Parallel testing**: Test against Rust implementation during development
3. **Backward compatibility**: Ensure existing C++ interfaces remain functional
4. **Documentation**: Update README.md with new features and usage

## Chapter 4: Implementation Steps

### 4.1 Foundation Infrastructure (Phase 1)

#### 4.1.1 Build System & Dependencies
- [x] CMakeLists.txt with yaml-cpp dependency
- [x] Basic project structure with src/ and include/ directories
- [x] C++17 standard configuration
- [x] Add new source files to CMakeLists.txt as they are created
- [ ] Consider adding test framework (Google Test or similar)

#### 4.1.2 Command Line Interface
- [x] Create `include/cli_parser.hpp` header file
- [x] Create `src/cli_parser.cpp` implementation
- [x] Implement `CLIParser::parse()` method using getopt_long
- [x] Add command-line option validation logic
- [x] Implement `printUsage()` method
- [x] Implement `printLicense()` method
- [x] Add license file reading functionality
- [x] Add LICENSE file to project root
- [x] Integration with main.cpp for all CLI options
- [x] Support for --help, --license, --reset, --remove-rules options
- [x] Proper error handling and validation

#### 4.1.3 Configuration Data Structures
- [x] Create `include/config.hpp` header file
- [x] Define `PortConfig` struct with all required fields
- [x] Define `MacConfig` struct with all required fields
- [x] Define `FilterConfig` struct with all required fields
- [x] Define `SectionConfig` struct with all required fields
- [x] Define `Config` root struct with all required fields
- [x] Add validation methods for each config type
- [x] Add YAML serialization support using yaml-cpp
- [x] Complete YAML template specializations for all config types
- [x] Support for optional fields using std::optional
- [x] Integration with existing rule system enums and types
- [x] **Rule order preservation using ordered containers**

### 4.2 Core Infrastructure (Phase 1 continued)

#### 4.2.1 Configuration Parser
- [x] Create `include/config_parser.hpp` header
- [x] Implement `src/config_parser.cpp` with complete functionality
- [x] Add YAML parsing for root Config object
- [x] Add YAML parsing for FilterConfig section
- [x] Add YAML parsing for custom sections
- [x] Add YAML parsing for PortConfig objects
- [x] Add YAML parsing for MacConfig objects
- [x] Add error handling and validation
- [x] Add support for default values
- [x] Add comprehensive error messages
- [x] Integration with yaml-cpp library
- [x] File and string-based configuration loading

#### 4.2.2 Command Execution System
- [x] Create `include/system_utils.hpp` header file (provides command execution functionality)
- [x] Create `src/system_utils.cpp` implementation (provides command execution functionality)
- [x] Implement command execution through `SystemUtils::executeCommand()` method
- [x] Add process output capture (stdout/stderr)
- [x] Add error handling and status checking
- [x] Add system requirements validation
- [x] Add iptables availability checking
- [x] Add root privilege verification
- [x] Create dedicated `include/command_executor.hpp` header file (enhanced functionality)
- [x] Create dedicated `src/command_executor.cpp` implementation (enhanced functionality)
- [x] Implement `CommandResult` structure with comprehensive result information
- [x] Add logging functionality with multiple log levels (None, Error, Warning, Info, Debug)
- [x] Add support for different iptables tables (filter, nat, mangle, raw)
- [x] Add enhanced iptables-specific methods (listRules, removeRuleByLineNumber, setChainPolicy, flushChain)
- [x] Add argument escaping and command building utilities
- [x] Add timestamp-based logging with proper output streams
- [x] Add comprehensive error reporting and structured command results

### 4.3 Rule System Enhancement (Phase 2)

#### 4.3.1 Base Rule System
- [x] Base `Rule` class with virtual methods
- [x] `Direction`, `Action`, `Protocol` enumerations
- [x] `InterfaceConfig` structure
- [x] Basic rule hierarchy (TcpRule, UdpRule, MacRule)
- [x] Enhanced comment generation matching Rust patterns
- [x] Improved interface comment formatting
- [x] Support for subnet list handling

#### 4.3.2 TCP Rule Implementation
- [x] Basic `TcpRule` class structure
- [x] Constructor with port, direction, action parameters
- [x] Basic `getComment()` implementation
- [x] Basic `buildIptablesCommand()` implementation
- [x] `matches()` method implementation
- [x] Enhanced port forwarding support
- [x] Complete iptables command building with all options
- [x] Support for interface specifications (-i/-o)
- [x] Support for subnet filtering (-s)
- [x] Support for MAC source filtering

#### 4.3.3 UDP Rule Implementation
- [x] Basic `UdpRule` class structure
- [x] Complete implementation similar to TcpRule
- [x] UDP-specific command generation
- [x] Port forwarding support for UDP
- [x] Interface and subnet support

#### 4.3.4 MAC Rule Implementation
- [x] Basic `MacRule` class structure
- [x] Enhanced MAC rule comment generation
- [x] Input direction validation (MAC rules only in INPUT)
- [x] Complete iptables command building for MAC rules
- [x] Interface support (input interface only)
- [x] Subnet filtering support

#### 4.3.5 New Rule Types
- [x] Create `PortForwardRule` class for NAT table rules
- [x] Implement port forwarding iptables commands
- [x] Support for REDIRECT target
- [x] Support for PREROUTING chain
- [x] Create `PolicyRule` class for chain policies
- [x] Implement policy setting commands (-P)

**Implementation Details:**
- **Port Forwarding**: Implemented in existing `TcpRule` and `UdpRule` classes using `forward_port` parameter and `buildPortForwardingCommand()` methods instead of separate `PortForwardRule` class
- **NAT Table Rules**: Port forwarding functionality uses NAT table PREROUTING chain with REDIRECT target, integrated into TCP/UDP rule classes
- **REDIRECT Target**: Full support implemented in `TcpRule::buildPortForwardingCommand()` and `UdpRule::buildPortForwardingCommand()` methods
- **PREROUTING Chain**: Complete support implemented across rule classes and `IptablesManager` for NAT table operations
- **Policy Management**: Implemented in `IptablesManager` and `RuleManager` classes using `CommandExecutor::setChainPolicy()` instead of separate `PolicyRule` class
- **Policy Commands**: Full support for `-P` iptables commands through `setChainPolicy()`, `resetPolicies()`, and policy configuration processing
- **Integration**: All new rule types are fully integrated with YAML configuration processing, rule management, and command execution systems

### 4.4 Rule Management Enhancement (Phase 3)

#### 4.4.1 Enhanced RuleManager
- [x] Basic `RuleManager` class structure
- [x] `addRule()` method implementation
- [x] `clearRules()` method implementation
- [x] `getAllRules()` method implementation
- [x] Complete `removeRule()` implementation
- [x] Complete `applyRules()` implementation  
- [x] Complete `removeAllRules()` implementation
- [x] Complete `setPolicy()` implementation
- [x] Complete `resetPolicies()` implementation
- [x] Implement `getRulesByComment()` method
- [x] Implement `getRulesByDirection()` method
- [x] Complete `executeIptablesCommand()` implementation
- [x] Complete `getRuleLineNumbers()` implementation
- [x] Implement `removeRulesBySignature()` method
- [x] Implement `removeAllYamlRules()` method
- [x] Implement `resetAllPolicies()` method
- [x] Add support for multiple iptables tables
- [x] Add line number based deletion logic

**Implementation Details:**
- **Rule Management**: Complete implementations for adding, removing, and clearing rules with proper memory management
- **Rule Application**: Full iptables command execution through CommandExecutor with comprehensive error handling
- **Policy Management**: Support for setting and resetting chain policies (INPUT/OUTPUT/FORWARD) in filter table
- **Rule Querying**: Filtering rules by comment patterns and direction with efficient search algorithms
- **YAML Rule Management**: Signature-based rule identification and removal matching Rust implementation patterns
- **Multi-table Support**: Operations across filter, nat, and mangle tables with proper chain validation
- **Line Number Deletion**: Descending order deletion to prevent index shifting during rule removal
- **Comment Parsing**: Regex-based parsing of iptables output to extract line numbers for targeted rule removal
- **Error Handling**: Comprehensive error reporting with detailed failure messages for all operations

#### 4.4.2 Enhanced IptablesManager
- [x] Basic `IptablesManager` class structure
- [x] Basic method stubs for main functionality
- [x] Helper method stubs for parsing
- [x] Complete `loadConfig()` implementation
- [x] Complete `processFilterConfig()` implementation (full implementation with CommandExecutor)
- [x] Complete `processPortConfig()` implementation (full implementation with iptables commands)
- [x] Complete `processMacConfig()` implementation (full implementation with iptables commands)
- [x] ConfigParser integration
- [x] SystemUtils integration for validation
- [x] Comprehensive error handling
- [x] Integration with main application workflow
- [x] Complete `parseDirection()` implementation
- [x] Complete `parseAction()` implementation  
- [x] Complete `parseProtocol()` implementation
- [x] Complete `parseInterface()` implementation
- [x] Implement rule replacement logic (remove then add)
- [x] Add actual iptables command generation and execution
- [x] Add CommandExecutor integration (fully implemented)

**Implementation Details:**
- **Helper Method Parsing**: Complete string-to-enum conversions with case-insensitive matching and comprehensive fallback handling
- **Direction Parsing**: Supports standard names (input/output/forward) and shorthand aliases (in/out/fwd) with Input as safe default
- **Action Parsing**: Supports multiple action names (accept/allow, drop/deny, reject) with Accept as safe default
- **Protocol Parsing**: Case-insensitive TCP/UDP parsing with TCP as default for unknown protocols
- **Interface YAML Parsing**: Flexible interface configuration supporting both scalar strings and object notation with input/output fields
- **Legacy Compatibility**: Support for both modern (input/output) and legacy (in/out) field names in YAML interface specifications
- **Error Handling**: Graceful fallback to safe defaults with warning messages for invalid configuration values
- **YAML Exception Safety**: Proper YAML::Exception handling in interface parsing with detailed error reporting

### 4.5 Main Application Logic (Phase 4)

#### 4.5.1 Main Application
- [x] Basic `main.cpp` structure with exception handling
- [x] Integrate CLIParser for argument processing
- [x] Handle `--license` option
- [x] Handle `--remove-rules` option
- [x] Handle `--reset` option with config file
- [x] Handle `--debug` option (**✨ enhanced with multiport validation**)
- [x] Handle config file processing
- [x] Add proper error codes and messages
- [x] Add comprehensive error handling for all exception types
- [x] Add file system validation for config files
- [x] Add usage message for invalid arguments
- [x] Add system requirements validation integration
- [x] Add proper workflow for reset + config application

#### 4.5.2 Application Flow
- [x] Implement license display functionality
- [x] Implement rule removal without config
- [x] Implement rule reset before config application
- [x] Implement full config processing workflow
- [x] Add validation for root privileges
- [x] Add iptables availability checking
- [x] Add comprehensive error reporting
- [x] Add file existence and accessibility validation
- [x] Add proper status reporting for all operations
- [x] Add detailed success/failure messages

### 4.6 Configuration Processing Logic (Phase 4 continued)

#### 4.6.1 Filter Configuration
- [x] Process input/output/forward policies
- [x] Generate rule comment starting with "YAML:<<rule name>>:<<rule component ...>>:<<...>>"
- [x] Generate policy setting commands
- [x] Handle filter-section MAC rules
- [x] Validate policy values
- [x] Remove existing policies before setting new ones

**Implementation Details:**
- Added `policyToString()` helper function to convert Policy enum to iptables policy strings
- Implemented `getInterfaceComment()` helper to generate interface comment parts matching Rust patterns
- Added `getRuleLineNumbers()` function to parse iptables output and extract line numbers for rules with specific comments
- Implemented `removeRulesBySignature()` to remove existing rules by comment signature before adding new ones
- Enhanced `processFilterConfig()` to:
  - Set INPUT/OUTPUT/FORWARD policies using `CommandExecutor::setChainPolicy()`
  - Generate proper YAML comments for policy rules (format: "YAML:filter:input:i:any:o:any")
  - Remove conflicting rules before setting new policies
  - Process MAC rules in filter section using `processMacConfig()`
- All policy setting operations use the CommandExecutor with proper error handling and logging

#### 4.6.2 Port Configuration Processing
- [x] Process port rules in custom sections
- [x] Handle regular port rules (INPUT/OUTPUT/FORWARD)
- [x] Handle port forwarding rules (NAT table)
- [x] Support interface specifications
- [x] Support subnet filtering
- [x] Support MAC source filtering
- [x] Generate appropriate iptables commands
- [x] Remove existing rules with same signature

**Implementation Details:**
- Enhanced `processPortConfig()` to handle both regular and port forwarding rules
- Regular rules: Generate commands for filter table chains (INPUT/OUTPUT/FORWARD)
- Port forwarding: Generate commands for NAT table PREROUTING chain with REDIRECT target
- Comment format for regular rules: "YAML:section:port:N:i:interface:o:interface:mac:source"
- Comment format for forwarding: "YAML:section:port:N:forward:i:interface:o:interface:mac:source"
- Implemented subnet handling with comma-separated lists (-s subnet1,subnet2,...)
- Interface support for both input (-i) and output (-o) specifications
- MAC source filtering using `-m mac --mac-source` iptables module
- Protocol conversion (TCP/UDP) with proper iptables syntax
- Rule removal by signature before adding new rules to prevent duplicates

#### 4.6.3 MAC Configuration Processing
- [x] Process MAC rules in all sections
- [x] Validate INPUT direction requirement
- [x] Support interface specifications (input only)
- [x] Support subnet filtering  
- [x] Generate MAC filtering commands
- [x] Remove existing MAC rules with same signature

**Implementation Details:**
- Enhanced `processMacConfig()` with full iptables command generation
- Enforced INPUT direction validation (MAC rules only allowed in INPUT chain)
- Comment format: "YAML:section:mac:mac_address:i:interface:o:any"
- Interface support for input interface only (MAC rules constraint)
- Subnet filtering with comma-separated subnet lists
- Proper MAC module usage: `-m mac --mac-source mac_address`
- Rule removal by signature matching before adding new rules
- Error handling for invalid directions with detailed error messages

### 4.7 Advanced Features (Phase 4 continued)

#### 4.7.1 Rule Signature Management
- [x] Implement signature-based rule identification
- [x] Pattern: `YAML:section:type:details:interface:mac`
- [x] Support for different rule types in signatures
- [x] Comment parsing and matching logic
- [x] Line number extraction from iptables output

#### 4.7.2 Rule Removal Strategy
- [x] List rules with line numbers using `iptables -L --line-numbers`
- [x] Parse line numbers from iptables output
- [x] Find rules matching YAML comment patterns
- [x] Sort line numbers in descending order
- [x] Remove rules from highest to lowest line number
- [x] Support for different iptables tables (filter, nat, mangle)
- [x] Handle non-existent chains gracefully

#### 4.7.3 Port Forwarding Implementation
- [x] Use NAT table PREROUTING chain
- [x] Generate REDIRECT target commands
- [x] Support `--to-port` parameter
- [x] Handle interface specifications for forwarding
- [x] Support MAC source filtering in forwarding rules
- [x] Proper signature generation for forwarding rules

### 4.8 Testing and Validation (Phase 5)

#### 4.8.1 Unit Test Infrastructure
- [ ] Set up test directory structure
- [ ] Choose and configure test framework (Google Test recommended)
- [ ] Add test targets to CMakeLists.txt
- [ ] Create test utilities and mocks

#### 4.8.2 Configuration Testing
- [ ] Test YAML parsing with valid configurations
- [ ] Test YAML parsing with invalid configurations
- [ ] Test configuration validation
- [ ] Test default value handling
- [ ] Test error message generation

#### 4.8.3 Rule Generation Testing
- [ ] Test TCP rule command generation
- [ ] Test UDP rule command generation
- [ ] Test MAC rule command generation
- [ ] Test port forwarding rule generation
- [ ] Test policy rule generation
- [ ] Test comment signature generation

#### 4.8.4 Command Execution Testing
- [ ] Mock iptables command execution
- [ ] Test command success and failure scenarios
- [ ] Test output parsing
- [ ] Test error handling
- [ ] Test different iptables tables

#### 4.8.5 Integration Testing
- [ ] Test complete configuration processing
- [ ] Test rule application workflow
- [ ] Test rule removal workflow
- [ ] Test with example.yaml configuration
- [ ] Test error scenarios and recovery

#### 4.8.6 Compatibility Testing
- [ ] Compare output with Rust implementation
- [ ] Test identical YAML configurations
- [ ] Verify iptables command compatibility
- [ ] Test rule signature compatibility
- [ ] Performance comparison

### 4.9 Documentation and Polish (Final Phase)

#### 4.9.1 Code Documentation
- [ ] Add comprehensive header comments
- [ ] Document all public methods
- [ ] Add usage examples
- [ ] Document configuration format
- [ ] Add troubleshooting guide

#### 4.9.2 User Documentation
- [ ] Update README.md with new features
- [ ] Add configuration examples
- [ ] Document command-line options
- [ ] Add build and installation instructions
- [ ] Create migration guide from Rust version

#### 4.9.3 Error Handling and Logging
- [ ] Enhance error messages with context
- [ ] Add debug logging throughout
- [ ] Add configuration validation messages
- [ ] Add progress indicators for long operations
- [ ] Add verbose mode option

This implementation plan ensures a systematic approach to porting the Rust functionality while maintaining the object-oriented design principles of the existing C++ codebase.

## Chapter 5: Implementation Verification Summary

### 5.1 Tested and Verified Components (as of current verification)

**✅ Build System & Dependencies**
- CMake configuration with yaml-cpp dependency is working correctly
- All source files are properly included and building successfully
- C++17 standard is configured and working
- Project structure with src/ and include/ directories is complete

**✅ Command Line Interface**
- All CLI options are implemented and working: --help, --license, --reset, --remove-rules
- Argument parsing using getopt_long is complete and functional
- Usage and license display are working correctly
- Error handling and validation are comprehensive
- Integration with main.cpp is complete

**✅ Configuration Data Structures**
- All configuration structs are implemented: PortConfig, MacConfig, FilterConfig, SectionConfig, Config
- YAML serialization with yaml-cpp is complete and working
- Configuration validation methods are implemented
- Support for optional fields using std::optional is working
- Integration with existing rule system enums and types is complete
- **Rule order preservation using ordered containers is implemented and tested**

**✅ Configuration Parser**
- YAML parsing for all configuration types is working
- File and string-based configuration loading is functional
- Error handling and validation are comprehensive
- Integration with yaml-cpp library is complete
- **Section order preservation from YAML is working correctly**

**✅ System Utilities & Command Execution**
- System requirements validation (root privileges, iptables availability)
- Command execution through `SystemUtils::executeCommand()`
- Process output capture and error handling
- Iptables version checking and availability verification

**✅ Main Application Logic**
- Complete main.cpp with all workflow scenarios
- Proper exception handling for all error types
- File system validation for configuration files
- Integration with all CLI options and system validation
- Comprehensive status reporting and error messages

**✅ Rule Order Preservation (CRITICAL FEATURE)**
- Sections are processed in exact YAML document order
- Rules within sections maintain their order (ports → mac → interface)
- Individual rules within each type preserve their sequence
- Uses `std::vector<std::pair<std::string, SectionConfig>>` for ordered sections
- Uses `-A` (append) instead of `-I` (insert) for iptables commands
- **Verified through live testing: rules appear in iptables in correct order**

### 5.2 Verified Functionality Through sudo Testing

**✅ Successful Operations Tested:**
- `./build/iptables-compose-cpp --help` - displays usage information
- `./build/iptables-compose-cpp --license` - displays MIT license
- `sudo ./build/iptables-compose-cpp example.yaml` - processes configuration successfully
- `sudo ./build/iptables-compose-cpp --remove-rules` - removes YAML rules successfully  
- `sudo ./build/iptables-compose-cpp --reset example.yaml` - resets and applies config successfully
- **Rule order preservation testing** - verified that iptables rules appear in exact YAML order

**✅ Configuration Processing Verified:**
- Filter section processing (policies and MAC rules)
- Custom section processing (ports and MAC rules)
- Port configuration with subnets, interfaces, and MAC sources
- MAC configuration with direction and interface validation
- Port forwarding configuration parsing
- Complex YAML structure parsing with nested configurations
- **Section order preservation**: first_section → second_section → third_section
- **Rule order within sections**: ports first, then MAC rules, in document order

### 5.3 Phase 4.1 Implementation Status Summary

**Phase 4.1 Foundation Infrastructure is COMPLETE ✅**

All items in Phase 4.1 have been successfully implemented and verified:

- **4.1.1 Build System & Dependencies**: ✅ Complete and working
- **4.1.2 Command Line Interface**: ✅ Complete and working  
- **4.1.3 Configuration Data Structures**: ✅ Complete and working

### 5.4 Additional Phases Significantly Advanced

**Phase 4.2 Core Infrastructure**: ✅ Complete
- Configuration Parser: ✅ Complete
- Command Execution System: ✅ Complete (both SystemUtils and enhanced CommandExecutor)

**Phase 4.5 Main Application Logic**: ✅ Complete
- All application workflows implemented and tested

**Phase 4.4.2 Enhanced IptablesManager**: ~70% Complete
- Basic structure and integration complete
- Configuration processing implemented (currently with logging)
- Missing: Actual iptables command generation and execution

### 5.5 Next Priority Items for Full Functionality

1. **Actual iptables command generation and execution** in IptablesManager
2. **Rule signature matching and removal** for YAML comment-based identification
3. **Port forwarding rule implementation** (NAT table rules)
4. **Policy setting implementation** (INPUT/OUTPUT/FORWARD policies)
5. **Enhanced rule management** with line number-based deletion

The foundation (Phase 4.1) is completely implemented and the application successfully handles configuration parsing, validation, and the overall workflow. The core infrastructure is in place for implementing the remaining iptables-specific functionality.

### 5.6 ✨ **NEW: Multiport Implementation (Phase 6) ✅ COMPLETE**

#### 5.6.1 Configuration Enhancement ✅
- [x] **Enhanced `PortConfig` structure with optional `range` field**
- [x] **Mutual exclusivity validation between `port` and `range`**
- [x] **Range format validation ("start-end" syntax)**
- [x] **Port number bounds checking (1-65535)**
- [x] **Range logic validation (start < end)**
- [x] **YAML encode/decode support for range arrays**
- [x] **Comprehensive error messaging for invalid ranges**

#### 5.6.2 Command Generation ✅
- [x] **Multiport iptables command generation (`-m multiport --dports`)**
- [x] **Range syntax conversion ("1000-2000" → "1000:2000")**
- [x] **Multiple range concatenation with commas**
- [x] **Integration with existing rule processing pipeline**
- [x] **Backward compatibility with single port syntax**
- [x] **Enhanced rule comment generation for multiport rules**

#### 5.6.3 Validation and Testing ✅
- [x] **Comprehensive range validation in `PortConfig::isValid()`**
- [x] **Error message generation for validation failures**
- [x] **Integration with rule validator for multiport rules**
- [x] **Test configuration files (`test_multiport.yaml`, `simple_multiport_test.yaml`)**
- [x] **Invalid configuration testing (`invalid_multiport_test.yaml`)**
- [x] **Live testing with actual iptables commands**
- [x] **Debug mode validation without applying rules**

#### 5.6.4 Documentation and Examples ✅
- [x] **Updated example.yaml with multiport syntax**
- [x] **Comprehensive test configurations**
- [x] **Error handling demonstrations**
- [x] **Documentation updates in README.md**

### 5.7 Testing and Validation (Phase 7) ✅ **COMPLETE**

#### 5.7.1 Live Testing ✅
- [x] **Successful compilation and building**
- [x] **Configuration parsing validation**
- [x] **Multiport syntax validation**
- [x] **Error detection for invalid configurations**
- [x] **Rule order validation**
- [x] **Debug mode testing**
- [x] **Backward compatibility verification**

#### 5.7.2 Configuration Testing ✅
- [x] **Valid multiport configurations**
- [x] **Invalid multiport configurations (both port and range)**
- [x] **Invalid multiport configurations (neither port nor range)**
- [x] **Invalid range formats**
- [x] **Port forwarding restriction testing**
- [x] **Mutual exclusivity validation**

### 5.8 Documentation and Polish (Final Phase) ✅ **COMPLETE**

#### 5.8.1 Documentation Updates ✅
- [x] **Updated README.md with multiport features**
- [x] **Updated STATUS.md with implementation status**
- [x] **Updated IMPLEMENT.md with multiport details**
- [x] **Configuration examples and syntax documentation**
- [x] **Troubleshooting guide for multiport issues**

### 5.9 ✨ **NEW: Multichain Implementation (Phase 6.3.3) ✅ COMPLETE**

#### 6.3.3 Rule Generation Enhancement ✅
- [x] **Complete `ChainRule` class implementation extending base `Rule` class**
- [x] **Chain jump command generation (`-j CUSTOM_CHAIN`) with full iptables syntax**
- [x] **Enhanced `TcpRule` with optional chain target support (`target_chain` parameter)**
- [x] **Enhanced `UdpRule` with optional chain target support (`target_chain` parameter)**
- [x] **Enhanced `MacRule` with optional chain target support (`target_chain` parameter)**
- [x] **Advanced rule comment generation for chain-based signatures**
- [x] **Comprehensive validation for chain vs. action mutual exclusivity**
- [x] **Enhanced rule signature system with chain call support**
- [x] **Complete support for interface-based chain calls**
- [x] **Updated rule matching logic for chain-enabled rules**
- [x] **YAML conversion template specialization for ChainRule class**
- [x] **Chain dependency validation with circular dependency detection**

#### Advanced Chain Features ✅
- [x] **Base `Rule` class enhanced with `target_chain_` member and `getTargetString()` method**
- [x] **Chain target validation with name format checking**
- [x] **Enhanced `addTargetArgs()` method for action/chain resolution**
- [x] **Mutual exclusivity validation between port forwarding and chain targets**
- [x] **Advanced comment generation with chain information included**
- [x] **Rule validator enhancement with `hasCircularChainDependencies()` implementation**

## Chapter 6: Multichain Support Implementation Plan

## 6.1 Feature Overview

The multichain feature allows users to create custom iptables chains with organized rule sets that can be called from other rules. This provides better rule organization, reusability, and modularity in firewall configuration.

### 6.1.1 Configuration Structure Analysis

Based on `example.yaml`, the multichain feature supports:

1. **Chain Reference in Rules**: Existing sections can reference custom chains using `chain` field
2. **Custom Chain Definitions**: New top-level sections defining chain structure with rules
3. **Hierarchical Rule Organization**: Rules grouped within chains for better organization

Example configuration pattern:
```yaml
# Section referencing a custom chain
mac_filter:
  interface:
    input: "eth1"
    chain: mac_rules_eth1    # References custom chain

# Custom chain definition
mac_rules_eth1:
  chain:
    - name: "MAC_RULES_ETH1"
      action: accept
      rules:
        enb1_mac:
          mac:
            - mac-source: "00:11:22:33:44:55"
              direction: input
              allow: true
        enb2_mac:
          mac:
            - mac-source: "aa:bb:cc:dd:ee:ff"
              direction: input
              allow: true
```

### 6.1.2 iptables Implementation Strategy

The feature translates to iptables commands:
1. **Chain Creation**: `iptables -N CUSTOM_CHAIN_NAME`
2. **Chain Rules**: `iptables -A CUSTOM_CHAIN_NAME -m mac --mac-source ... -j ACCEPT`
3. **Chain Calls**: `iptables -A INPUT -i eth1 -j MAC_RULES_ETH1`
4. **Chain Management**: Proper creation order and cleanup

## 6.2 Architecture Enhancement

### 6.2.1 Configuration Structure Updates

**New Configuration Types**:
```cpp
struct ChainRuleConfig {
    std::string name;                                    // Chain name (e.g., "MAC_RULES_ETH1")
    Action action = Action::Accept;                      // Default action for chain
    std::map<std::string, SectionConfig> rules;         // Named rule groups within chain
};

struct ChainConfig {
    std::vector<ChainRuleConfig> chain;                  // Array of chain definitions
};

struct InterfaceConfig {
    std::optional<std::string> input;                    // Input interface
    std::optional<std::string> output;                   // Output interface
    std::optional<std::string> chain;                    // ✨ NEW: Custom chain to call
};

struct SectionConfig {
    std::vector<PortConfig> ports;
    std::vector<MacConfig> mac_rules;
    std::optional<InterfaceConfig> interface;            // ✨ ENHANCED: Now supports chain calls
    std::optional<ChainConfig> chain_config;             // ✨ NEW: For chain definition sections
};
```

**Enhanced Config Root Structure**:
```cpp
struct Config {
    std::optional<FilterConfig> filter;
    std::vector<std::pair<std::string, SectionConfig>> custom_sections;  // Preserves order
    std::map<std::string, ChainConfig> chain_definitions;                // ✨ NEW: Extracted chain definitions
};
```

### 6.2.2 Rule Processing Flow Enhancement

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   YAML Parser   │───→│  Chain Extractor │───→│  Dependency     │
│   (enhanced)    │    │   (NEW)          │    │  Resolver (NEW) │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ Section Parser  │    │  Chain Manager   │    │  Rule Generator │
│   (enhanced)    │    │   (NEW)          │    │   (enhanced)    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ IptablesManager │    │  Command Executor│    │   System        │
│   (enhanced)    │    │   (enhanced)     │    │   (iptables)    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## 6.3 Implementation Tasks

### 6.3.1 Phase 6.1: Configuration Structure Enhancement
- [x] Update `InterfaceConfig` to support optional `chain` field
- [x] Create `ChainRuleConfig` structure for individual chain definitions
- [x] Create `ChainConfig` structure for chain arrays
- [x] Update `SectionConfig` to include optional `ChainConfig`
- [x] Update `Config` to support chain definitions extraction
- [x] Add YAML parsing support for new structures
- [x] Add validation for chain references and definitions
- [x] Update existing YAML template specializations
- [x] Add chain definition extraction logic during config parsing
- [x] Add chain reference validation (ensure referenced chains exist)

### 6.3.2 Phase 6.2: Chain Management System
- [x] Create `ChainManager` class for custom chain operations
- [x] Implement `createChain()` method for iptables chain creation
- [x] Implement `deleteChain()` method for iptables chain removal
- [x] Implement `flushChain()` method for clearing chain rules
- [x] Implement `chainExists()` method for chain validation
- [x] Add chain dependency resolution logic
- [x] Add chain creation order management
- [x] Add chain cleanup and removal logic
- [x] Add error handling for chain operations
- [x] Add chain listing and validation methods

### 6.3.3 Phase 6.3: Rule Generation Enhancement
- [x] Create `ChainRule` class extending base `Rule` class
- [x] Implement chain jump command generation (`-j CUSTOM_CHAIN`)
- [x] Update `TcpRule` to support chain target instead of action
- [x] Update `UdpRule` to support chain target instead of action
- [x] Update `MacRule` to support chain target instead of action
- [x] Add chain rule comment generation for signatures
- [x] Add validation for chain vs. action mutual exclusivity
- [x] Enhance rule signature system to handle chain calls
- [x] Add support for interface-based chain calls
- [x] Update rule matching logic for chain-enabled rules

### 6.3.4 Phase 6.4: Configuration Processing Enhancement
- [x] Update `ConfigParser` to handle chain definitions
- [x] Add chain definition parsing to `parseYamlFile`
- [x] Update `IptablesManager::processConfiguration` to handle chains
- [x] Add `processChainConfigurations` method to `IptablesManager`

### 6.3.5 Phase 6.5: Command Execution Enhancement
- [x] Add chain creation commands to `CommandExecutor`
- [x] Update rule removal to handle chain cleanup
- [x] Add error handling for chain operations
- [x] Update logging for chain operations

### 6.3.6 Phase 6.6: Integration and Workflow
- [x] Update `IptablesManager` for chain support
- [x] Add chain processing to configuration workflow
- [x] Update rule removal workflow for chains
- [x] Add validation for circular chain references

## 6.4 Technical Implementation Details

### 6.4.1 Chain Creation Strategy
```bash
# Chain creation sequence:
iptables -N MAC_RULES_ETH1                              # Create custom chain
iptables -A MAC_RULES_ETH1 -m mac --mac-source ... -j ACCEPT  # Add rules to chain
iptables -A INPUT -i eth1 -j MAC_RULES_ETH1             # Call chain from main rule
```

### 6.4.2 Chain Signature System
**Chain Definition Rules**:
- Format: `YAML:chain:CHAIN_NAME:rule_type:details`
- Example: `YAML:chain:MAC_RULES_ETH1:mac:00:11:22:33:44:55`

**Chain Call Rules**:
- Format: `YAML:section:chain_call:CHAIN_NAME:interface`
- Example: `YAML:mac_filter:chain_call:MAC_RULES_ETH1:i:eth1`

### 6.4.3 Dependency Resolution
1. **Parse all chain definitions** from configuration
2. **Extract chain references** from sections
3. **Validate references** (ensure all referenced chains are defined)
4. **Detect circular dependencies** in chain calls
5. **Order chain creation** to satisfy dependencies
6. **Create chains first**, then populate with rules
7. **Add chain calls last** after all chains are ready

### 6.4.4 Error Handling Strategy
- **Missing chain definitions**: Error if section references undefined chain
- **Circular dependencies**: Error if chains reference each other circularly
- **Chain creation failures**: Detailed error reporting with recovery options
- **Rule conflicts**: Validate that chain calls don't conflict with actions
- **Chain cleanup**: Proper cleanup of created chains on failure

### 6.4.5 Validation Enhancements
```cpp
class ChainValidator {
public:
    static std::vector<ValidationWarning> validateChainConfig(const Config& config);
    static bool validateChainReferences(const Config& config);
    static bool detectCircularDependencies(const Config& config);
    static std::vector<std::string> getChainCreationOrder(const Config& config);
    
private:
    static void buildDependencyGraph(const Config& config, 
                                   std::map<std::string, std::set<std::string>>& graph);
    static bool hasCycle(const std::map<std::string, std::set<std::string>>& graph);
};
```

## 6.5 Configuration Examples

### 6.5.1 Basic Chain Definition and Usage
```yaml
# Section with chain call
web_filter:
  interface:
    input: "eth0"
    chain: web_security_chain

# Chain definition
web_security_chain:
  chain:
    - name: "WEB_SECURITY_CHAIN"
      action: accept
      rules:
        allowed_ips:
          ports:
            - port: 80
              subnet: ["192.168.1.0/24"]
              allow: true
        blocked_ips:
          ports:
            - port: 80
              subnet: ["10.0.0.0/8"]
              allow: false
```

### 6.5.2 Complex Multi-Chain Configuration
```yaml
# Main security filtering
security_filter:
  interface:
    input: "eth0"
    chain: main_security_chain

# SSH access control
ssh_filter:
  interface:
    input: "any"
    chain: ssh_access_chain

# Main security chain
main_security_chain:
  chain:
    - name: "MAIN_SECURITY_CHAIN"
      action: drop
      rules:
        web_traffic:
          ports:
            - port: 80
              allow: true
            - port: 443
              allow: true
        call_ssh_check:
          interface:
            chain: ssh_access_chain

# SSH access chain
ssh_access_chain:
  chain:
    - name: "SSH_ACCESS_CHAIN"
      action: drop
      rules:
        admin_access:
          ports:
            - port: 22
              subnet: ["192.168.1.0/24"]
              allow: true
```

### 6.5.3 Advanced Chain Organization
```