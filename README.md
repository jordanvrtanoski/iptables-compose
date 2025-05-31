# iptables-compose-cpp

A C++ implementation of iptables-compose, providing a structured way to manage iptables rules using YAML configuration files. This tool makes it easier to maintain, version control, and deploy firewall rules across systems.

## 🚀 Features

- **YAML Configuration**: Define iptables rules using human-readable YAML files
- **Rule Types**: Support for TCP, UDP, and MAC-based rules
- **Multiport Support**: Configure multiple ports and port ranges efficiently using iptables multiport extension
- **Rule Management**: Automatic rule identification with comments for easy management
- **Rule Order Validation**: Intelligent analysis to detect unreachable and redundant rules
- **Policy Management**: Control INPUT, OUTPUT, and FORWARD chain policies
- **Port Forwarding**: Built-in support for NAT-based port forwarding
- **Interface Rules**: Interface-specific rule configuration
- **Subnet Filtering**: Network-based access control
- **MAC Filtering**: Hardware address-based filtering
- **Safe Operations**: Rules are replaced atomically to prevent conflicts
- **Debug Mode**: Configuration validation without applying changes

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
    - range:
        - "8000-8100"
        - "9000-9100"
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

## 🔧 SystemD Deployment

For production environments, `iptables-compose-cpp` can be deployed as a systemd service to automatically apply firewall rules at system startup with proper network timing dependencies.

### Quick SystemD Setup

1. **Install the service** (after building and installing the binary):
   ```bash
   sudo ./install-systemd-service.sh
   ```

2. **Configure your firewall** at `/etc/network/iptables-compose.yaml`:
   ```bash
   sudo cp systemd-config-example.yaml /etc/network/iptables-compose.yaml
   sudo nano /etc/network/iptables-compose.yaml  # Edit as needed
   ```

3. **Enable and start the service**:
   ```bash
   sudo systemctl enable iptables-compose.service
   sudo systemctl start iptables-compose.service
   ```

### Key SystemD Features

- **🚀 Automatic Startup**: Rules applied automatically after network interfaces are ready
- **⏰ Proper Timing**: Runs after network setup, before SSH and other services
- **🔒 Security Hardened**: Service runs with minimal required privileges
- **📊 Monitoring**: Full integration with systemd journal for logging
- **🔄 Reload Support**: Configuration changes via `systemctl reload`

### Service Management

```bash
# Check service status
sudo systemctl status iptables-compose.service

# View service logs
sudo journalctl -u iptables-compose.service

# Reload configuration
sudo systemctl reload iptables-compose.service
```

**📖 For detailed deployment instructions, troubleshooting, and production best practices, see [SYSTEMD_DEPLOYMENT.md](SYSTEMD_DEPLOYMENT.md)**

## 📁 Project Structure

```
iptables-compose-cpp/
├── 📄 CMakeLists.txt           # Build configuration
├── 📄 build.sh                # Build script
├── 📄 install_dependencies.sh # Dependency installer
├── 📁 include/                # Header files
│   ├── cli_parser.hpp         # Command line argument parsing
│   ├── config.hpp             # Configuration structures (with multiport support)
│   ├── config_parser.hpp      # YAML configuration parser
│   ├── command_executor.hpp   # Iptables command execution
│   ├── iptables_manager.hpp   # Main iptables interface
│   ├── rule.hpp              # Base rule class
│   ├── tcp_rule.hpp          # TCP rule implementation (with multiport)
│   ├── udp_rule.hpp          # UDP rule implementation (with multiport)
│   ├── mac_rule.hpp          # MAC rule implementation
│   ├── rule_manager.hpp      # Rule collection management
│   ├── rule_validator.hpp    # Rule order validation and conflict detection
│   └── system_utils.hpp     # System utilities
├── 📁 src/                   # Source files
│   ├── main.cpp             # Application entry point
│   ├── cli_parser.cpp       # CLI parsing implementation
│   ├── config.cpp           # Configuration handling (with multiport validation)
│   ├── config_parser.cpp    # YAML parsing logic
│   ├── command_executor.cpp # Command execution engine
│   ├── iptables_manager.cpp # Main business logic (with multiport processing)
│   ├── rule_manager.cpp     # Rule management
│   ├── rule_validator.cpp   # Rule validation implementation
│   ├── tcp_rule.cpp        # TCP rule logic (with multiport support)
│   ├── udp_rule.cpp        # UDP rule logic (with multiport support)
│   ├── mac_rule.cpp        # MAC rule logic
│   └── system_utils.cpp    # System interaction
├── 📄 example.yaml         # Example configuration
├── 📄 test_multiport.yaml  # Multiport configuration examples
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
    
    - range:
        - "1000-2000"
        - "3000-4000"
        - "8080-8090"
      protocol: tcp|udp
      direction: input|output|forward
      allow: true|false
      subnet: ["10.0.0.0/8"]
      mac-source: "aa:bb:cc:dd:ee:ff"
      interface:
        input: eth0
        output: eth1
  
  mac:
    - mac-source: "aa:bb:cc:dd:ee:ff"  # MAC address (required)
      direction: input          # Direction (input only for MAC rules)
      allow: true|false         # Allow or deny (default: true)
      subnet: ["192.168.0.0/16"] # Source subnets (optional)
      interface:
        input: eth0             # Input interface (optional)
```

### Multiport Configuration Examples

```yaml
# Example 1: Web services with multiple port ranges
web_services:
  ports:
    - port: 80
      allow: true
    - port: 443
      allow: true
    - range:
        - "3000-3010"
        - "8000-8010"
        - "9000-9010"
      allow: true
      subnet: ["192.168.1.0/24"]

# Example 2: Database services
database_services:
  ports:
    - range:
        - "3306-3309"
        - "5432-5435"
        - "27017-27019"
      allow: true
      subnet: ["10.0.0.0/8"]
      interface:
        input: eth1

# Example 3: Gaming servers
game_servers:
  ports:
    - range:
        - "7777-7787"
        - "25565-25575"
      protocol: tcp
      allow: true
    - range:
        - "7777-7787"
      protocol: udp
      allow: true
```

### Generated iptables Commands

The multiport implementation generates optimized iptables commands:

```bash
iptables -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp -m multiport --dports 1000:2000,3000:4000,8080:8090 -j ACCEPT
iptables -A INPUT -p tcp -m multiport --dports 3306:3309,5432:5435 -s 10.0.0.0/8 -i eth1 -j ACCEPT
```

## 🔒 Security Considerations

- **Root Privileges**: This tool requires root access to modify iptables rules
- **Rule Validation**: All rules are validated before application, including multiport syntax
- **Mutual Exclusivity**: Port and range fields are mutually exclusive to prevent configuration errors
- **Port Range Limits**: iptables multiport extension supports up to 15 port specifications per rule
- **Port Forwarding Restriction**: Port ranges cannot be used with port forwarding (iptables limitation)
- **Atomic Operations**: Rules are replaced atomically to prevent security gaps
- **Comment-based Management**: Rules are tracked using comments for safe removal

## 🐛 Troubleshooting

### Common Issues

1. **Permission Denied**: Ensure you're running with sudo/root privileges
2. **iptables not found**: Install iptables package for your distribution
3. **Build Errors**: Check that all dependencies are installed
4. **YAML Parse Errors**: Validate your YAML syntax and structure
5. **Multiport Errors**:
   - Ensure port ranges don't exceed 15 specifications per rule
   - Verify range format is "start-end" (e.g., "1000-2000")
   - Don't use both `port` and `range` in the same rule
   - Port forwarding not supported with ranges

### Debug Mode

Enable validation without applying rules:
```bash
./iptables-compose-cpp --debug config.yaml
```

This will validate your configuration, including multiport syntax, without modifying iptables.

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