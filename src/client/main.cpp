/**
 * Sting - WASP VPN Client
 * Main Entry Point & GUI Launcher
 */

#include <thread>
#include <iostream>

#include "network_thread.hpp"
#include "gui.hpp"

// Graphics & UI Backend Includes
#include <imgui.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_opengl3.h>
#include <GLFW/glfw3.h>
#include "common.hpp"

// Global state shared between GUI and Network threads
AppState app_state;

// ==========================================
// GLFW Error Callback
// ==========================================
void glfw_error_callback(int error, const char* description) {
    std::cerr << "GLFW Error " << error << ": " << description << std::endl;
}

// ==========================================
// MAIN
// ==========================================
int main(int argc, char** argv) {
    // 1. Initialize GLFW (The Windowing Library)
    glfwSetErrorCallback(glfw_error_callback);
    if (!glfwInit()) {
        std::cerr << "Failed to initialize GLFW" << std::endl;
        return 1;
    }

    // Set OpenGL version (e.g., 3.3 for modern compatibility)
    const char* glsl_version = "#version 150";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE); // Required for macOS

    // 2. Create Window
    GLFWwindow* window = glfwCreateWindow(800, 500, "Sting - WASP VPN Client", nullptr, nullptr);
    if (window == nullptr) {
        std::cerr << "Failed to create GLFW window" << std::endl;
        glfwTerminate();
        return 1;
    }
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1); // Enable V-Sync to cap framerate

    // 3. Initialize Dear ImGui
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard; // Enable Keyboard Controls

    // Apply our custom style
    apply_style();

    // Initialize ImGui backends for GLFW and OpenGL
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init(glsl_version);

    // 4. Parse Command Line Arguments (Optional)
    // You can pre-fill the connection info from the command line
    if (argc >= 4) {
        ParsedAddress addr = parse_address(argv[1]);
        app_state.server_host = addr.host;
        app_state.server_port = addr.port;
        app_state.username = argv[2];
        app_state.password = argv[3];
    } else {
        // Load from config file or use defaults
        app_state.log_queue.push({LogLevel::INFO, "Hint: You can pass server, user, and pass as arguments."});
    }

    // 5. Launch Network Thread
    // This thread will handle all the LWS, TUN, and crypto logic in the background.
    app_state.log_queue.push({LogLevel::INFO, "Starting network backend..."});
    std::thread network_backend(network_thread_main, &app_state);

    app_state.log_queue.push({LogLevel::SUCCESS, R"(
 ______     ______   __     __   __     ______
/\  ___\   /\__  _\ /\ \   /\ "-.\ \   /\  ___\
\ \___  \  \/_/\ \/ \ \ \  \ \ \-.  \  \ \ \__ \
 \/\_____\    \ \_\  \ \_\  \ \_\\"\_\  \ \_____\
  \/_____/     \/_/   \/_/   \/_/ \/_/   \/_____/
     Web Augmented Secure Protocol Client v1.5
                    lumen | cv2
)"});

    // ==========================================
    // MAIN RENDER LOOP
    // ==========================================
    while (!glfwWindowShouldClose(window)) {
        // Poll for events (keyboard, mouse, window resize)
        glfwPollEvents();

        // Start a new ImGui frame
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        // Call our main UI rendering function
        render_ui(app_state);

        // Render the frame
        ImGui::Render();

        // Get window size for the viewport
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);

        // Clear the screen
        glClearColor(0.94f, 0.94f, 0.94f, 1.00f);
        glClear(GL_COLOR_BUFFER_BIT);

        // Draw ImGui data to the screen
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        // Swap front and back buffers
        glfwSwapBuffers(window);
    }

    // ==========================================
    // CLEANUP
    // ==========================================

    // 1. Signal the network thread to stop
    app_state.disconnect_request = true; // Close active connections
    app_state.exit_requested = true;     // Tells the while() loop to break

    // 2. Wait for it to finish (this will no longer hang)
    if (network_backend.joinable()) {
        network_backend.join();
    }

    // 3. Shut down Graphics
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();

    glfwDestroyWindow(window);
    glfwTerminate();

    return 0;
}