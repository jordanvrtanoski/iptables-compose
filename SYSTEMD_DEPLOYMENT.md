# SystemD Deployment Guide

This guide explains how to deploy `iptables-compose-cpp` as a systemd service for automatic firewall configuration on system startup.

## Overview

The systemd service ensures that your iptables firewall rules are automatically applied:
- **After** network interfaces are ready
- **Before** services like SSH start
- **With** proper error handling and logging
- **Using** atomic rule application for safety

## Installation

### Prerequisites

1. **Install the binary** to `/usr/sbin/iptables-compose-cpp`
2. **Create configuration directory**: `/etc/network/`
3. **Have systemd** installed (most modern Linux distributions)

### Quick Installation

1. **Run the installation script** (as root):
   ```bash
   sudo ./install-systemd-service.sh
   ```

2. **Create your configuration** at `/etc/network/iptables-compose.yaml`:
   ```bash
   sudo cp systemd-config-example.yaml /etc/network/iptables-compose.yaml
   sudo nano /etc/network/iptables-compose.yaml  # Edit as needed
   ```

3. **Enable and start the service**:
   ```bash
   sudo systemctl enable iptables-compose.service
   sudo systemctl start iptables-compose.service
   ```

### Manual Installation

If you prefer manual installation:

1. **Copy the service file**:
   ```bash
   sudo cp iptables-compose.service /etc/systemd/system/
   sudo chmod 644 /etc/systemd/system/iptables-compose.service
   ```

2. **Reload systemd**:
   ```bash
   sudo systemctl daemon-reload
   ```

## Configuration

### Service Dependencies

The service is configured to run:
- **After**: `network.target`, `network-online.target`, `systemd-networkd.service`, `NetworkManager.service`
- **Before**: `sshd.service` (to ensure firewall is active before SSH starts)
- **Wants**: `network-online.target` (ensures network is actually configured)

### Security Features

The service includes several security hardening features:
- Runs as root (required for iptables)
- Restricts system calls to essential ones
- Protects home directories
- Prevents privilege escalation
- Memory execution protection where possible

### Configuration File

Create your firewall configuration at `/etc/network/iptables-compose.yaml`. See `systemd-config-example.yaml` for a production-ready example.

## Usage

### Basic Commands

```bash
# Check service status
sudo systemctl status iptables-compose.service

# View service logs
sudo journalctl -u iptables-compose.service

# Reload configuration (applies new rules)
sudo systemctl reload iptables-compose.service

# Restart service
sudo systemctl restart iptables-compose.service

# Stop service (doesn't remove existing rules)
sudo systemctl stop iptables-compose.service

# Disable auto-start
sudo systemctl disable iptables-compose.service
```

### Configuration Management

```bash
# Test configuration without applying
sudo /usr/sbin/iptables-compose-cpp --dry-run /etc/network/iptables-compose.yaml

# Apply configuration manually
sudo /usr/sbin/iptables-compose-cpp /etc/network/iptables-compose.yaml

# Reset and apply (clears managed rules first)
sudo /usr/sbin/iptables-compose-cpp --reset /etc/network/iptables-compose.yaml
```

## Monitoring

### Service Status

The service uses `Type=oneshot` with `RemainAfterExit=yes`, meaning:
- It runs once at startup
- Systemd considers it "active" after successful execution
- Configuration reloads trigger re-execution

### Logging

All output goes to the system journal:
```bash
# Follow logs in real-time
sudo journalctl -u iptables-compose.service -f

# Show recent logs
sudo journalctl -u iptables-compose.service -n 50

# Show logs since last boot
sudo journalctl -u iptables-compose.service -b
```

### Health Checks

```bash
# Verify service is loaded and enabled
systemctl is-enabled iptables-compose.service

# Check if service completed successfully
systemctl is-active iptables-compose.service

# Verify rules are applied (look for signature comments)
sudo iptables -L -n --line-numbers | grep "iptables-compose-cpp"
```

## Troubleshooting

### Common Issues

1. **Service fails to start**
   ```bash
   # Check service logs
   sudo journalctl -u iptables-compose.service -n 20
   
   # Verify configuration syntax
   sudo /usr/sbin/iptables-compose-cpp --validate /etc/network/iptables-compose.yaml
   ```

2. **Configuration not applied**
   ```bash
   # Check if file exists and is readable
   sudo ls -la /etc/network/iptables-compose.yaml
   
   # Test configuration manually
   sudo /usr/sbin/iptables-compose-cpp /etc/network/iptables-compose.yaml
   ```

3. **Network timing issues**
   ```bash
   # Check network service status
   systemctl status network.target network-online.target
   
   # Verify network is ready
   networkctl status
   ```

### Emergency Recovery

If firewall rules block access:

1. **From console access** (not SSH):
   ```bash
   # Remove all managed rules
   sudo /usr/sbin/iptables-compose-cpp --remove-rules
   
   # Or flush all iptables rules (nuclear option)
   sudo iptables -F
   sudo iptables -P INPUT ACCEPT
   sudo iptables -P OUTPUT ACCEPT
   sudo iptables -P FORWARD ACCEPT
   ```

2. **Disable the service temporarily**:
   ```bash
   sudo systemctl disable iptables-compose.service
   ```

## Best Practices

### Configuration Management

1. **Version control** your configuration files
2. **Test changes** on non-production systems first
3. **Use comments** in your YAML for documentation
4. **Backup** working configurations

### Security Considerations

1. **Start restrictive** - use `drop` policies by default
2. **Allow only necessary** ports and protocols
3. **Use source restrictions** for sensitive services
4. **Monitor logs** for blocked connection attempts

### Deployment Strategy

1. **Stage deployments** - test on dev/staging first
2. **Have console access** before making changes
3. **Use gradual rollouts** for production changes
4. **Monitor services** after rule changes

## Integration

### With Configuration Management

The service integrates well with:
- **Ansible**: Deploy configuration files and restart service
- **Puppet**: Manage service state and configuration
- **Chef**: Template configurations and manage service
- **Salt**: Orchestrate firewall changes across infrastructure

### With Monitoring

Monitor the service with:
- **Systemd journal** forwarding to log aggregation
- **Process monitoring** to ensure service health
- **Network monitoring** to verify rule effectiveness
- **Security monitoring** for blocked connection attempts

## Validation

Before deploying to production:

1. **Syntax validation**:
   ```bash
   sudo systemd-analyze verify /etc/systemd/system/iptables-compose.service
   ```

2. **Dependency check**:
   ```bash
   systemctl list-dependencies iptables-compose.service
   ```

3. **Boot simulation**:
   ```bash
   # Test on a non-production system
   sudo reboot
   # Verify service starts and rules are applied
   ```

---

For additional help, see the main project documentation or check the service logs for specific error messages. 