#!/bin/bash

# Function to print colored output
print_message() {
    echo -e "\e[1;34m==>\e[0m \e[1m$1\e[0m"
}

print_error() {
    echo -e "\e[1;31mError:\e[0m \e[1m$1\e[0m"
}

print_success() {
    echo -e "\e[1;32mSuccess:\e[0m \e[1m$1\e[0m"
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to detect Linux distribution
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$ID"
    elif command_exists lsb_release; then
        lsb_release -si | tr '[:upper:]' '[:lower:]'
    else
        echo "unknown"
    fi
}

# Function to install dependencies based on distribution
install_dependencies() {
    local distro=$1
    
    print_message "Detected distribution: $distro"
    print_message "Installing dependencies..."

    case $distro in
        "ubuntu"|"debian"|"linuxmint")
            sudo apt-get update
            sudo apt-get install -y \
                build-essential \
                cmake \
                libyaml-cpp-dev \
                iptables \
                git
            ;;
            
        "fedora")
            sudo dnf update
            sudo dnf install -y \
                gcc-c++ \
                cmake \
                yaml-cpp-devel \
                iptables \
                git
            ;;
            
        "centos"|"rhel"|"rocky"|"almalinux")
            sudo yum update
            sudo yum install -y \
                gcc-c++ \
                cmake \
                yaml-cpp-devel \
                iptables \
                git
            ;;
            
        "arch"|"manjaro")
            sudo pacman -Syu
            sudo pacman -S --noconfirm \
                base-devel \
                cmake \
                yaml-cpp \
                iptables \
                git
            ;;
            
        "opensuse"|"suse")
            sudo zypper update
            sudo zypper install -y \
                gcc-c++ \
                cmake \
                yaml-cpp-devel \
                iptables \
                git
            ;;
            
        *)
            print_error "Unsupported distribution: $distro"
            print_message "Please install the following packages manually:"
            echo "- build-essential/gcc-c++ (C++ compiler and build tools)"
            echo "- cmake (version 3.14 or later)"
            echo "- yaml-cpp (YAML parser library)"
            echo "- iptables (firewall management)"
            echo "- git (version control)"
            exit 1
            ;;
    esac
}

# Function to verify installations
verify_installations() {
    print_message "Verifying installations..."
    
    local missing_packages=()
    
    # Check CMake
    if ! command_exists cmake; then
        missing_packages+=("cmake")
    else
        cmake_version=$(cmake --version | head -n1 | cut -d' ' -f3)
        print_success "CMake version: $cmake_version"
    fi
    
    # Check g++
    if ! command_exists g++; then
        missing_packages+=("g++")
    else
        gpp_version=$(g++ --version | head -n1 | cut -d' ' -f4)
        print_success "G++ version: $gpp_version"
    fi
    
    # Check iptables
    if ! command_exists iptables; then
        missing_packages+=("iptables")
    else
        iptables_version=$(iptables --version | cut -d' ' -f2)
        print_success "iptables version: $iptables_version"
    fi
    
    # Check yaml-cpp
    if [ ! -f /usr/include/yaml-cpp/yaml.h ] && [ ! -f /usr/local/include/yaml-cpp/yaml.h ]; then
        missing_packages+=("yaml-cpp")
    else
        print_success "yaml-cpp is installed"
    fi
    
    # Report any missing packages
    if [ ${#missing_packages[@]} -ne 0 ]; then
        print_error "The following packages are missing:"
        for pkg in "${missing_packages[@]}"; do
            echo "- $pkg"
        done
        return 1
    fi
    
    print_success "All required packages are installed!"
    return 0
}

# Main script execution
main() {
    print_message "Starting dependency installation..."
    
    # Check if running as root
    if [ "$EUID" -eq 0 ]; then
        print_error "Please do not run this script as root"
        print_message "The script will use sudo when needed"
        exit 1
    fi
    
    # Detect distribution and install dependencies
    distro=$(detect_distro)
    install_dependencies "$distro"
    
    # Verify installations
    if verify_installations; then
        print_success "Dependencies installation completed successfully!"
        print_message "You can now proceed with building the project:"
        echo "mkdir build && cd build"
        echo "cmake .."
        echo "make"
    else
        print_error "Some dependencies are missing. Please install them manually."
        exit 1
    fi
}

# Run main function
main 