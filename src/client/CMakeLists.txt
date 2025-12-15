cmake_minimum_required(VERSION 3.20)

# 1. Fetch GLFW
include(FetchContent)
FetchContent_Declare(
        glfw
        GIT_REPOSITORY https://github.com/glfw/glfw.git
        GIT_TAG        3.3.8
)
FetchContent_MakeAvailable(glfw)

# 2. Fetch ImGui
FetchContent_Declare(
        imgui
        GIT_REPOSITORY https://github.com/ocornut/imgui.git
        GIT_TAG        v1.89.9
)
FetchContent_MakeAvailable(imgui)

# === Define ImGui as a Static Library ===
add_library(imgui_lib STATIC
        ${imgui_SOURCE_DIR}/imgui.cpp
        ${imgui_SOURCE_DIR}/imgui_draw.cpp
        ${imgui_SOURCE_DIR}/imgui_tables.cpp
        ${imgui_SOURCE_DIR}/imgui_widgets.cpp
        ${imgui_SOURCE_DIR}/backends/imgui_impl_glfw.cpp
        ${imgui_SOURCE_DIR}/backends/imgui_impl_opengl3.cpp
        ${imgui_SOURCE_DIR}/misc/cpp/imgui_stdlib.cpp
)

target_include_directories(imgui_lib PUBLIC
        ${imgui_SOURCE_DIR}
        ${imgui_SOURCE_DIR}/backends
        ${imgui_SOURCE_DIR}/misc/cpp
)

target_link_libraries(imgui_lib PRIVATE glfw)
if (APPLE)
    target_link_libraries(imgui_lib PRIVATE OpenGL::GL)
endif()

# 3. Define the Sting Executable
add_executable(sting
        main.cpp
        gui.cpp
        network_thread.cpp
)

# === FIX: Include LibWebSockets Headers ===
target_include_directories(sting PRIVATE ${LWS_INCLUDE_DIR})
# ==========================================

# 4. Link Libraries
target_link_libraries(sting PRIVATE
        libwasp
        ${LWS_LIBRARY}
        OpenSSL::Crypto
        pthread
        imgui_lib
        glfw
)

# 5. MacOS Frameworks
if (APPLE)
    find_package(OpenGL REQUIRED)
    target_link_libraries(sting PRIVATE
            OpenGL::GL
            "-framework Cocoa"
            "-framework IOKit"
            "-framework CoreVideo"
    )
endif()

if (UNIX AND NOT APPLE)
    find_package(OpenGL REQUIRED)
    target_link_libraries(sting PRIVATE OpenGL::GL)
endif()