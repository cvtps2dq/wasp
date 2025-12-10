cmake_minimum_required(VERSION 3.20)

project(WASP
        VERSION 1.0.0
        DESCRIPTION "WebAugmentedSecureProtocol VPN"
        LANGUAGES CXX
)

# ==========================================
# 1. Platform & Path Setup (Fixes macOS Linker)
# ==========================================

# Explicitly reject Windows
if(WIN32)
    message(FATAL_ERROR "Windows is not supported. #opensourcerules")
endif()

# Auto-detect Homebrew prefix to fix linker paths
find_program(BREW_PROG brew)
if(BREW_PROG)
    execute_process(COMMAND ${BREW_PROG} --prefix OUTPUT_VARIABLE BREW_PREFIX OUTPUT_STRIP_TRAILING_WHITESPACE)
    message(STATUS "Found Homebrew at: ${BREW_PREFIX}")

    # Global hints for find_package and linker
    include_directories(${BREW_PREFIX}/include)
    link_directories(${BREW_PREFIX}/lib)
    set(CMAKE_PREFIX_PATH ${BREW_PREFIX} ${CMAKE_PREFIX_PATH})
endif()

# Enforce C++23
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ==========================================
# 2. Dependencies
# ==========================================

# OpenSSL
find_package(OpenSSL 3.0 REQUIRED)

# Libwebsockets (PkgConfig is safest for this lib)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LWS REQUIRED libwebsockets)

# Threads
find_package(Threads REQUIRED)

# ==========================================
# 3. Compiler Flags
# ==========================================

add_library(project_warnings INTERFACE)
target_compile_options(project_warnings INTERFACE
        -Wall -Wextra -Wpedantic -Wshadow -Wno-unused-parameter
)

# ==========================================
# 4. Target Definition
# ==========================================

add_executable(wasp_vpn
        src/main.cpp
        src/wasp_protocol.cpp
        src/wasp_session.cpp
        src/wasp_defs.hpp
        src/wasp_crypto.hpp
        src/wasp_session.hpp
        src/worker_pool.cpp
        src/worker_pool.hpp
        src/session_manager.cpp
        src/session_manager.hpp
)

# Include Directories
target_include_directories(wasp_vpn PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${LWS_INCLUDE_DIRS}
        ${OPENSSL_INCLUDE_DIR}
)

# Link Libraries
target_link_libraries(wasp_vpn PRIVATE
        project_warnings
        OpenSSL::SSL
        OpenSSL::Crypto
        ${LWS_LIBRARIES}
        Threads::Threads
)

# Explicitly tell linker where LWS is (Vital for macOS)
if(LWS_LIBRARY_DIRS)
    target_link_directories(wasp_vpn PRIVATE ${LWS_LIBRARY_DIRS})
endif()