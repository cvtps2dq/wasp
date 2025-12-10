cmake_minimum_required(VERSION 3.20)
project(WASP_VPN VERSION 1.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Dependencies (OpenSSL, LibWebSockets)
find_package(OpenSSL REQUIRED)
# LibWebSockets is often found via pkg-config or standard paths
find_path(LWS_INCLUDE_DIR libwebsockets.h)
find_library(LWS_LIBRARY websockets)

# Subdirectories
add_subdirectory(src/libwasp)
add_subdirectory(src/server)
add_subdirectory(src/client)