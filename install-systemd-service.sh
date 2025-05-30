#!/bin/bash

# iptables-compose systemd service installation script
# This script installs and configures the iptables-compose systemd service

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
SERVICE_FILE="iptables-compose.service"
SYSTEMD_DIR="/etc/systemd/system"
BINARY_PATH="/usr/sbin/iptables-compose-cpp"
CONFIG_DIR="/etc/network"
CONFIG_FILE="$CONFIG_DIR/iptables-compose.yaml"

echo -e "${GREEN}iptables-compose systemd service installer${NC}"
echo "=========================================="

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: This script must be run as root${NC}"
   exit 1
fi

# Check if service file exists
if [[ ! -f "$SERVICE_FILE" ]]; then
    echo -e "${RED}Error: Service file '$SERVICE_FILE' not found${NC}"
    echo "Please run this script from the directory containing the service file"
    exit 1
fi

# Check if binary exists
if [[ ! -f "$BINARY_PATH" ]]; then
    echo -e "${YELLOW}Warning: Binary not found at $BINARY_PATH${NC}"
    echo "Please ensure iptables-compose-cpp is installed to $BINARY_PATH"
fi

# Create config directory if it doesn't exist
if [[ ! -d "$CONFIG_DIR" ]]; then
    echo "Creating configuration directory: $CONFIG_DIR"
    mkdir -p "$CONFIG_DIR"
fi

# Check if config file exists
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo -e "${YELLOW}Warning: Configuration file not found at $CONFIG_FILE${NC}"
    echo "You'll need to create a configuration file before enabling the service"
fi

# Install service file
echo "Installing service file to $SYSTEMD_DIR/$SERVICE_FILE"
cp "$SERVICE_FILE" "$SYSTEMD_DIR/"

# Set proper permissions
chmod 644 "$SYSTEMD_DIR/$SERVICE_FILE"

# Reload systemd
echo "Reloading systemd daemon"
systemctl daemon-reload

# Check service status
echo "Checking service syntax"
if systemctl status iptables-compose.service &>/dev/null || [[ $? -eq 3 ]]; then
    echo -e "${GREEN}✓ Service file installed successfully${NC}"
else
    echo -e "${RED}✗ Error in service file syntax${NC}"
    exit 1
fi

echo ""
echo "Installation complete!"
echo ""
echo "Next steps:"
echo "1. Create configuration file: $CONFIG_FILE"
echo "2. Enable the service: systemctl enable iptables-compose.service"
echo "3. Start the service: systemctl start iptables-compose.service"
echo ""
echo "Useful commands:"
echo "  systemctl status iptables-compose.service    # Check service status"
echo "  systemctl reload iptables-compose.service    # Reload configuration"
echo "  journalctl -u iptables-compose.service       # View service logs"
echo "  systemctl disable iptables-compose.service   # Disable service"
echo ""
echo -e "${GREEN}Service installed successfully!${NC}" 