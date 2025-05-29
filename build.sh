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

# Get the absolute path of the workspace
WORKSPACE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Function to ensure we're in the workspace directory
ensure_workspace() {
    if [ "$PWD" != "$WORKSPACE_DIR" ]; then
        print_message "Switching to workspace directory: $WORKSPACE_DIR"
        cd "$WORKSPACE_DIR" || {
            print_error "Failed to switch to workspace directory"
            exit 1
        }
    fi
}

# Function to clean build directory
clean_build() {
    print_message "Cleaning build directory..."
    if [ -d "build" ]; then
        rm -rf build
    fi
}

# Function to create and enter build directory
setup_build_dir() {
    print_message "Setting up build directory..."
    mkdir -p build
    cd build || {
        print_error "Failed to enter build directory"
        exit 1
    }
}

# Function to run CMake
run_cmake() {
    print_message "Running CMake..."
    cmake .. || {
        print_error "CMake configuration failed"
        exit 1
    }
}

# Function to run make
run_make() {
    print_message "Building project..."
    make -j$(nproc) || {
        print_error "Build failed"
        exit 1
    }
}

# Function to verify build
verify_build() {
    print_message "Verifying build..."
    if [ -f "iptables-compose-cpp" ]; then
        print_success "Build successful! Binary created: build/iptables-compose-cpp"
    else
        print_error "Build verification failed - binary not found"
        exit 1
    fi
}

# Main build process
main() {
    print_message "Starting build process..."
    
    # Ensure we're in the workspace directory
    ensure_workspace
    
    # Clean previous build if it exists
    clean_build
    
    # Setup build directory
    setup_build_dir
    
    # Run CMake
    run_cmake
    
    # Run make
    run_make
    
    # Verify build
    verify_build
    
    # Return to workspace directory
    cd "$WORKSPACE_DIR" || {
        print_error "Failed to return to workspace directory"
        exit 1
    }
    
    print_success "Build process completed successfully!"
    print_message "You can find the binary at: build/iptables-compose-cpp"
}

# Run main function
main 