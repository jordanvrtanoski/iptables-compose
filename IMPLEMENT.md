# Implementation Plan: iptables-compose-cpp

This document outlines the implementation plan for porting the Rust-based iptables-compose application to C++. The goal is to maintain feature parity while leveraging the existing C++ class structure.

## Chapter 1: Architecture Overview

### 1.1 Current State Analysis

The existing C++ codebase has a solid foundation with:
- **Rule hierarchy**: Base `Rule` class with specialized implementations (`TcpRule`, `UdpRule`, `MacRule`)
- **Management layer**: `IptablesManager` for high-level operations, `RuleManager` for rule collection management
- **Build system**: CMake with yaml-cpp dependency already configured

### 1.2 Rust Implementation Architecture

The Rust implementation follows a functional approach with these key components:
1. **CLI parsing**: Using `clap` for command-line argument handling
2. **Configuration structures**: Nested structs representing YAML configuration
3. **Rule processing**: Functions that transform configuration into iptables commands
4. **Command execution**: Direct system calls to iptables binary
5. **Rule management**: Signature-based rule identification and removal

### 1.3 Target C++ Architecture

The C++ implementation will maintain object-oriented principles:

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Application   │───→│   IptablesManager │───→│   RuleManager   │
│   (main.cpp)    │    │                  │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   ConfigParser  │    │  CommandExecutor │    │   Rule classes  │
│                 │    │                  │    │  (TCP/UDP/MAC)  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## Chapter 2: Logic Explanation

### 2.1 Configuration Processing

The Rust implementation processes YAML configurations in this sequence:

1. **YAML Parsing**: Deserialize YAML into structured data
2. **Filter Policies**: Set default chain policies (INPUT, OUTPUT, FORWARD)
3. **Section Processing**: Handle custom sections with port and MAC rules
4. **Rule Generation**: Convert configuration to iptables commands

Key configuration structures:
- `Config`: Root configuration object
- `FilterConfig`: Chain policies and filter-specific MAC rules
- `SectionConfig`: Custom sections with ports and MAC rules
- `PortConfig`: Individual port rule configuration
- `MacConfig`: MAC address filtering rules

### 2.2 Rule Management Logic

#### 2.2.1 Rule Identification
Rules are identified using comment-based signatures:
```
YAML:section:type:details:interface:mac
```

Examples:
- `YAML:web:port:80:i:eth0:o:any:mac:any`
- `YAML:filter:mac:aa:bb:cc:dd:ee:ff:i:any:o:any`

#### 2.2.2 Rule Removal Strategy
1. List existing rules with line numbers
2. Find rules matching comment patterns
3. Remove rules in reverse order (highest line number first)
4. This prevents line number shifting issues

#### 2.2.3 Rule Application
1. Remove existing rules with same signature
2. Build new iptables command
3. Execute command with proper error handling

### 2.3 Command Line Interface

The Rust implementation supports:
- `config <file>`: Apply configuration from YAML file
- `--reset`: Reset all iptables rules before applying config
- `--remove-rules`: Remove all rules with YAML comments
- `--license`: Display license information

### 2.4 Rule Ordering Design

#### 2.4.1 Importance of Rule Order in iptables
In iptables, rule order is critical because rules are evaluated sequentially from top to bottom within each chain. The first rule that matches a packet determines the action taken. This makes preserving the exact order of rules as they appear in the YAML configuration file essential for correct firewall behavior.

#### 2.4.2 Order Preservation Strategy
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

#### 2.4.3 iptables Command Strategy
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

#### 2.4.4 Safety Considerations for Remote Systems

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

#### 2.4.5 Rule Order Validation

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

### 2.5 Special Cases Handling

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
- [ ] Create `PortForwardRule` class for NAT table rules
- [ ] Implement port forwarding iptables commands
- [ ] Support for REDIRECT target
- [ ] Support for PREROUTING chain
- [ ] Create `PolicyRule` class for chain policies
- [ ] Implement policy setting commands (-P)

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