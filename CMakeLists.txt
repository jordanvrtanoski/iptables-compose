cmake_minimum_required(VERSION 3.14)
project(iptables-compose-cpp VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Find required packages
find_package(yaml-cpp REQUIRED)

# Add executable
add_executable(iptables-compose-cpp 
    src/main.cpp
    src/iptables_manager.cpp
    src/rule_manager.cpp
    src/rule.cpp
    src/tcp_rule.cpp
    src/udp_rule.cpp
    src/mac_rule.cpp
    src/chain_rule.cpp
    src/config.cpp
    src/config_parser.cpp
    src/cli_parser.cpp
    src/system_utils.cpp
    src/command_executor.cpp
    src/rule_validator.cpp
    src/chain_manager.cpp
)

# Include directories
target_include_directories(iptables-compose-cpp
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${YAML_CPP_INCLUDE_DIR}
)

# Link libraries
target_link_libraries(iptables-compose-cpp
    PRIVATE
        yaml-cpp
)

# Install target
install(TARGETS iptables-compose-cpp
    RUNTIME DESTINATION bin
) 