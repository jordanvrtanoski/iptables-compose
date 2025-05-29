# iptables-compose-cpp

A C++ implementation of iptables-compose, providing a structured way to manage iptables rules using YAML configuration files. This tool makes it easier to maintain, version control, and deploy firewall rules across systems.

## 🚀 Features

- **YAML Configuration**: Define iptables rules using human-readable YAML files
- **Rule Types**: Support for TCP, UDP, and MAC-based rules
- **Rule Management**: Automatic rule identification with comments for easy management
- **Policy Management**: Control INPUT, OUTPUT, and FORWARD chain policies
- **Port Forwarding**: Built-in support for NAT-based port forwarding
- **Interface Rules**: Interface-specific rule configuration
- **Subnet Filtering**: Network-based access control
- **MAC Filtering**: Hardware address-based filtering
- **Safe Operations**: Rules are replaced atomically to prevent conflicts

## 🛠️ Installation

### Quick Setup

Use the provided installation script for automated dependency setup:

```bash
./install_dependencies.sh
```

### Manual Installation

#### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install cmake libyaml-cpp-dev iptables build-essential
```

#### CentOS/RHEL/Fedora
```bash
sudo yum install cmake yaml-cpp-devel iptables gcc-c++ make
# OR for newer versions:
sudo dnf install cmake yaml-cpp-devel iptables gcc-c++ make
```

## 🔧 Building

### Using the Build Script (Recommended)
```bash
./build.sh
```

### Manual Build
```bash
mkdir build
cd build
cmake ..
make -j$(nproc)
```

The executable will be created as `build/iptables-compose-cpp`.

## 📋 Requirements

- **System**: Linux with iptables support
- **Compiler**: C++17 compatible compiler (GCC 7+, Clang 5+)
- **CMake**: Version 3.14 or later
- **Dependencies**: yaml-cpp library
- **Privileges**: Root access required for iptables operations

## 🚀 Usage

### Command Line Options

```bash
# Apply configuration
sudo ./iptables-compose-cpp config.yaml

# Reset all rules before applying (recommended)
sudo ./iptables-compose-cpp --reset config.yaml

# Remove all YAML-managed rules
sudo ./iptables-compose-cpp --remove-rules

# Display help
./iptables-compose-cpp --help

# Show license information
./iptables-compose-cpp --license
```

### Basic Example

```yaml
# config.yaml
filter:
  input: drop    # Default policy: drop all input
  output: accept # Allow all output
  
web:
  ports:
    - port: 80
      protocol: tcp
      direction: input
      allow: true
    - port: 443
      protocol: tcp
      direction: input
      allow: true

ssh:
  ports:
    - port: 22
      protocol: tcp
      direction: input
      allow: true
      subnet: ["192.168.1.0/24"]  # Only allow from local network
```

## 📁 Project Structure

```
iptables-compose-cpp/
├── 📄 CMakeLists.txt           # Build configuration
├── 📄 build.sh                # Build script
├── 📄 install_dependencies.sh # Dependency installer
├── 📁 include/                # Header files
│   ├── cli_parser.hpp         # Command line argument parsing
│   ├── config.hpp             # Configuration structures
│   ├── config_parser.hpp      # YAML configuration parser
│   ├── command_executor.hpp   # Iptables command execution
│   ├── iptables_manager.hpp   # Main iptables interface
│   ├── rule.hpp              # Base rule class
│   ├── tcp_rule.hpp          # TCP rule implementation
│   ├── udp_rule.hpp          # UDP rule implementation
│   ├── mac_rule.hpp          # MAC rule implementation
│   ├── rule_manager.hpp      # Rule collection management
│   └── system_utils.hpp     # System utilities
├── 📁 src/                   # Source files
│   ├── main.cpp             # Application entry point
│   ├── cli_parser.cpp       # CLI parsing implementation
│   ├── config.cpp           # Configuration handling
│   ├── config_parser.cpp    # YAML parsing logic
│   ├── command_executor.cpp # Command execution engine
│   ├── iptables_manager.cpp # Main business logic
│   ├── rule_manager.cpp     # Rule management
│   ├── tcp_rule.cpp        # TCP rule logic
│   ├── udp_rule.cpp        # UDP rule logic
│   ├── mac_rule.cpp        # MAC rule logic
│   └── system_utils.cpp    # System interaction
├── 📄 example.yaml         # Example configuration
├── 📄 IMPLEMENT.md         # Implementation documentation
└── 📄 LICENSE              # MIT License
```

## 📖 Configuration Reference

### Filter Section
```yaml
filter:
  input: accept|drop|reject     # INPUT chain policy
  output: accept|drop|reject    # OUTPUT chain policy  
  forward: accept|drop|reject   # FORWARD chain policy
  mac:                          # MAC rules in filter section
    - mac-source: "aa:bb:cc:dd:ee:ff"
      allow: true
      subnet: ["192.168.1.0/24"]
```

### Custom Sections
```yaml
section_name:
  ports:
    - port: 80                  # Port number (required)
      protocol: tcp|udp         # Protocol (default: tcp)
      direction: input|output|forward  # Direction (default: input)
      allow: true|false         # Allow or deny (default: true)
      subnet: ["10.0.0.0/8"]    # Allowed subnets (optional)
      forward: 8080             # Forward to port (optional, NAT)
      mac-source: "aa:bb:cc:dd:ee:ff"  # MAC filter (optional)
      interface:
        input: eth0             # Input interface (optional)
        output: eth1            # Output interface (optional)
  
  mac:
    - mac-source: "aa:bb:cc:dd:ee:ff"  # MAC address (required)
      direction: input          # Direction (input only for MAC rules)
      allow: true|false         # Allow or deny (default: true)
      subnet: ["192.168.0.0/16"] # Source subnets (optional)
      interface:
        input: eth0             # Input interface (optional)
```

## 🔒 Security Considerations

- **Root Privileges**: This tool requires root access to modify iptables rules
- **Rule Validation**: All rules are validated before application
- **Atomic Operations**: Rules are replaced atomically to prevent security gaps
- **Comment-based Management**: Rules are tracked using comments for safe removal

## 🐛 Troubleshooting

### Common Issues

1. **Permission Denied**: Ensure you're running with sudo/root privileges
2. **iptables not found**: Install iptables package for your distribution
3. **Build Errors**: Check that all dependencies are installed
4. **YAML Parse Errors**: Validate your YAML syntax and structure

### Debug Mode

Enable verbose logging by setting the log level in the CommandExecutor:
```cpp
CommandExecutor::setLogLevel(LogLevel::Debug);
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Inspired by docker-compose for container orchestration
- Built with modern C++ practices and CMake
- Uses yaml-cpp for configuration parsing